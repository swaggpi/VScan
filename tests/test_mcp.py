"""Tests for the vscan MCP server.

The tool *functions* are imported and called directly (not over the wire), and
exercised against ``samples/golden-app`` and ``samples/demo-app``. Navigation
tools run fully offline. Problem/fix tools either use ``offline=True`` or mock
the correlator's network boundary exactly like ``tests/test_correlate.py`` --
no test touches the real network.

If the optional ``mcp`` dependency is missing the whole module skips cleanly so
the core suite is unaffected.
"""

from __future__ import annotations

import json
import os
import shutil

import pytest

pytest.importorskip("mcp")  # optional dependency; skip the module without it

from scanner.correlate import enrich, osv  # noqa: E402
from scanner.mcp import server as S  # noqa: E402
from scanner.mcp import state  # noqa: E402

_HERE = os.path.dirname(__file__)
_ROOT = os.path.dirname(_HERE)
GOLDEN = os.path.join(_ROOT, "samples", "golden-app")
DEMO = os.path.join(_ROOT, "samples", "demo-app")

PYYAML_CVE = "CVE-2020-1747"
URLLIB3_CVE = "CVE-2021-33503"

# Recorded OSV records. PyYAML (5.3.1, reachable) is KEV + high EPSS and fixed
# in 5.4; urllib3 (1.25.8, unreachable) is a plain advisory fixed in 1.26.5.
_OSV_RECORDS = {
    "GHSA-pyyaml": {
        "id": "GHSA-pyyaml",
        "summary": "PyYAML load allows arbitrary code execution",
        "details": "The yaml.load function with the default loader is the vulnerable sink.",
        "aliases": [PYYAML_CVE],
        "database_specific": {"severity": "CRITICAL"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}
                ],
            }
        ],
    },
    "GHSA-urllib3": {
        "id": "GHSA-urllib3",
        "summary": "urllib3 CRLF injection",
        "details": "urllib3 before 1.26.5 mishandles request bodies.",
        "aliases": [URLLIB3_CVE],
        "database_specific": {"severity": "MEDIUM"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}
        ],
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.5"}]}
                ],
            }
        ],
    },
}

_IDS_BY_NAME = {"PyYAML": ["GHSA-pyyaml"], "urllib3": ["GHSA-urllib3"]}
_KEV_SET = {PYYAML_CVE}  # only PyYAML is actively exploited
_EPSS = {PYYAML_CVE: (0.92, 0.99), URLLIB3_CVE: (0.05, 0.30)}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Fresh on-disk cache and empty MCP caches for every test."""
    monkeypatch.setenv("VSCAN_CACHE_DIR", str(tmp_path / "vscan-cache"))
    state.clear_caches()
    yield
    state.clear_caches()


@pytest.fixture
def mocked_db(monkeypatch):
    """Patch every correlator network boundary with the recorded fixtures."""
    monkeypatch.setattr(
        osv, "query_batch",
        lambda queries: [_IDS_BY_NAME.get(q["package"]["name"], []) for q in queries],
    )
    monkeypatch.setattr(osv, "fetch_vuln", lambda vid: _OSV_RECORDS[vid])
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: set(_KEV_SET))
    monkeypatch.setattr(enrich, "query_epss", lambda cves: dict(_EPSS))


def _call(func, model_cls, **kwargs):
    return json.loads(func(model_cls(**kwargs)))


# -- Capability 1: NAVIGATE ---------------------------------------------------


def test_scan_overview_golden_counts():
    ov = _call(S.vscan_scan_overview, S.ScanOverviewInput, repo_path=GOLDEN)
    assert ov["entrypoints"] == 8
    assert ov["dependencies"]["total"] == 7
    assert ov["dependencies"]["pinned"] == 7
    assert "python" in ov["languages"]
    endpoints = {r["endpoint"] for r in ov["entrypoint_list"]["items"]}
    assert "POST /submit" in endpoints
    assert ov["entrypoint_list"]["total"] == 8


def test_find_locates_symbol():
    res = _call(S.vscan_find, S.FindInput, repo_path=GOLDEN, query="ingest")
    ids = {m["id"] for m in res["matches"]["items"]}
    assert "fn:services.py:ingest" in ids


def test_find_kind_filter():
    res = _call(S.vscan_find, S.FindInput, repo_path=GOLDEN, query="yaml", kind="dependency")
    kinds = {m["kind"] for m in res["matches"]["items"]}
    assert kinds == {"dependency"}
    assert any(m["id"] == "dep:PyPI:PyYAML" for m in res["matches"]["items"])


def test_describe_function_signature_and_callees():
    d = _call(S.vscan_describe, S.DescribeInput, repo_path=GOLDEN, node_id="fn:services.py:ingest")
    assert d["signature"] == "ingest(raw)"
    assert d["docstring"] and "load_yaml" in d["docstring"]
    assert "fn:services.py:load_yaml" in d["callees"]["functions"]
    assert d["location"]["file"] == "services.py"


def test_describe_dependency_reachability():
    d = _call(S.vscan_describe, S.DescribeInput, repo_path=GOLDEN, node_id="dep:PyPI:PyYAML")
    assert d["version"] == "5.3.1"
    assert d["reachable"] is True
    assert d["verdict"] == "reachable"
    assert "yaml.safe_load" in d["called_symbols"]


def test_describe_entrypoint_reaches():
    d = _call(S.vscan_describe, S.DescribeInput, repo_path=GOLDEN, node_id="ep:POST:/submit")
    assert d["method"] == "POST" and d["path"] == "/submit"
    assert "dep:PyPI:PyYAML" in d["reaches"]["reachable_dependencies"]


def test_call_graph_out_reaches_dependency():
    cg = _call(
        S.vscan_call_graph, S.CallGraphInput,
        repo_path=GOLDEN, node_id="fn:services.py:ingest", direction="out", depth=3,
    )
    node_ids = {n["id"] for n in cg["nodes"]}
    assert "fn:services.py:load_yaml" in node_ids
    assert "dep:PyPI:PyYAML" in node_ids


def test_call_graph_in_finds_caller():
    cg = _call(
        S.vscan_call_graph, S.CallGraphInput,
        repo_path=GOLDEN, node_id="fn:services.py:ingest", direction="in", depth=1,
    )
    node_ids = {n["id"] for n in cg["nodes"]}
    assert "fn:app.py:submit" in node_ids


def test_trace_entrypoint_reaches_pyyaml():
    t = _call(S.vscan_trace_entrypoint, S.TraceEntrypointInput,
              repo_path=GOLDEN, entrypoint_id="ep:POST:/submit")
    dep_ids = {rd["id"] for rd in t["reachable_dependencies"]}
    assert "dep:PyPI:PyYAML" in dep_ids
    pyyaml = next(rd for rd in t["reachable_dependencies"] if rd["id"] == "dep:PyPI:PyYAML")
    assert pyyaml["example_path"]  # a concrete path is recorded


def test_dep_reachers_pyyaml_submit():
    dr = _call(S.vscan_dep_reachers, S.DepReachersInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML")
    assert dr["verdict"] == "reachable"
    assert dr["reachable"] is True
    eps = {e["entrypoint"] for e in dr["entrypoints"]}
    assert "ep:POST:/submit" in eps


def test_demo_app_scan_overview_offline():
    ov = _call(S.vscan_scan_overview, S.ScanOverviewInput, repo_path=DEMO)
    assert ov["node_counts"].get("entrypoint", 0) >= 1
    assert ov["dependencies"]["total"] >= 1
    # a known demo-app dependency is discoverable
    res = _call(S.vscan_find, S.FindInput, repo_path=DEMO, query="PyYAML", kind="dependency")
    assert any("PyYAML" in m["id"] for m in res["matches"]["items"])


# -- Capability 2: DISCUSS PROBLEMS -------------------------------------------


def test_audit_ranks_reachable_kev_first(mocked_db):
    au = _call(S.vscan_audit, S.AuditInput, repo_path=GOLDEN)
    assert au["network_ok"] is True
    assert au["counts"]["findings"] == 2
    assert au["counts"]["reachable"] == 1
    top = au["findings"][0]
    assert top["dependency"] == "PyYAML"
    assert PYYAML_CVE in top["cve_ids"]
    assert top["reachable"] is True
    assert top["kev"] is True
    assert top["verdict"] == "reachable"
    # explain=True attaches advisory triage. (The usage tier only fires for deps
    # with no resolved static call edge; PyYAML is statically reached via
    # yaml.safe_load, so it correctly has triage but no usage block.)
    assert set(top["triage"]) >= {"affected", "confidence", "rationale"}
    assert "usage" not in top
    # the unreachable, non-KEV finding is ranked after the reachable KEV one
    assert au["findings"][1]["dependency"] == "urllib3"
    assert au["findings"][1]["reachable"] is False


def test_audit_no_explain_omits_advisory(mocked_db):
    au = _call(S.vscan_audit, S.AuditInput, repo_path=GOLDEN, explain=False)
    assert all("triage" not in f for f in au["findings"])


def test_audit_offline_returns_no_findings():
    au = _call(S.vscan_audit, S.AuditInput, repo_path=GOLDEN, offline=True)
    assert au["offline"] is True
    assert au["counts"]["findings"] == 0


def test_finding_detail_pyyaml(mocked_db):
    fd = _call(S.vscan_finding_detail, S.FindingDetailInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML")
    assert fd["reachable"] is True
    assert len(fd["cves"]) == 1
    cve = fd["cves"][0]
    assert PYYAML_CVE in cve["cve_ids"]
    assert "5.4" in cve["fixed_versions"]
    assert "yaml.load" in cve["details"]
    assert fd["reaching_entrypoints"]
    assert fd["triage"]


def test_finding_detail_no_findings(mocked_db):
    # Flask has no mocked advisory -> graceful "no findings" error.
    out = S.vscan_finding_detail(S.FindingDetailInput(repo_path=GOLDEN, dep_id="dep:PyPI:Flask"))
    assert out.startswith("Error:") and "no findings" in out


# -- Capability 3: FIX --------------------------------------------------------


def test_remediation_recommends_smallest_clearing_version(mocked_db):
    rem = _call(S.vscan_remediation, S.RemediationInput,
                repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML")
    assert rem["count"] == 1
    r = rem["remediations"][0]
    assert r["current_version"] == "5.3.1"
    assert r["recommended_version"] == "5.4"
    assert r["source_file"] == "requirements.txt"
    assert r["reachable"] is True
    assert "vscan_apply_upgrade" in r["next_step"]


def test_remediation_all_vulnerable_deps_reachable_first(mocked_db):
    rem = _call(S.vscan_remediation, S.RemediationInput, repo_path=GOLDEN)
    assert rem["count"] == 2
    # reachable PyYAML sorts before unreachable urllib3
    assert rem["remediations"][0]["dependency"] == "PyYAML"


def test_apply_upgrade_dry_run_diff_and_no_write(tmp_path):
    dst = tmp_path / "golden"
    shutil.copytree(GOLDEN, dst)
    req = dst / "requirements.txt"
    before = req.read_text()

    up = _call(S.vscan_apply_upgrade, S.ApplyUpgradeInput,
               repo_path=str(dst), dep_id="dep:PyPI:PyYAML", version="5.4", dry_run=True)
    assert up["applied"] is False
    assert up["source_file"] == "requirements.txt"
    assert "-PyYAML==5.3.1" in up["diff"]
    assert "+PyYAML==5.4" in up["diff"]
    # dry-run must NOT modify the file
    assert req.read_text() == before
    assert "PyYAML==5.3.1" in req.read_text()


def test_apply_upgrade_writes_when_not_dry_run(tmp_path):
    dst = tmp_path / "golden"
    shutil.copytree(GOLDEN, dst)
    req = dst / "requirements.txt"

    up = _call(S.vscan_apply_upgrade, S.ApplyUpgradeInput,
               repo_path=str(dst), dep_id="dep:PyPI:PyYAML", version="5.4", dry_run=False)
    assert up["applied"] is True
    text = req.read_text()
    assert "PyYAML==5.4\n" in text
    assert "PyYAML==5.3.1" not in text
    # every other pin is untouched
    assert "Flask==2.0.1" in text
    assert "requests==2.25.0" in text


def test_apply_upgrade_refuses_when_pin_absent(tmp_path):
    dst = tmp_path / "golden"
    shutil.copytree(GOLDEN, dst)
    # Rewrite PyYAML as a range so there is no exact '==' pin to edit.
    req = dst / "requirements.txt"
    req.write_text(req.read_text().replace("PyYAML==5.3.1", "PyYAML>=5.0"))
    state.clear_caches()
    out = S.vscan_apply_upgrade(
        S.ApplyUpgradeInput(repo_path=str(dst), dep_id="dep:PyPI:PyYAML", version="5.4")
    )
    assert out.startswith("Error:")
    assert "requirements.txt" in out


# -- error handling -----------------------------------------------------------


def test_invalid_repo_path_is_graceful():
    out = S.vscan_scan_overview(S.ScanOverviewInput(repo_path="/no/such/repo"))
    assert out.startswith("Error:") and "does not exist" in out


def test_unknown_node_is_graceful():
    out = S.vscan_describe(S.DescribeInput(repo_path=GOLDEN, node_id="fn:does.not:exist"))
    assert out.startswith("Error:") and "vscan_find" in out


def test_wrong_node_kind_is_graceful():
    # call_graph expects a function, not a dependency
    out = S.vscan_call_graph(
        S.CallGraphInput(repo_path=GOLDEN, node_id="dep:PyPI:PyYAML", direction="out")
    )
    assert out.startswith("Error:") and "expects a function" in out


def test_server_exposes_twelve_tools():
    assert len(S.mcp._tool_manager.list_tools()) == 12


# -- Capability 4: PROVE (the fix-and-prove loop) -----------------------------


def test_verify_fix_proves_pyyaml_and_leaves_tree_untouched(mocked_db):
    # Prove non-mutation: capture the real GOLDEN manifest before and after.
    req = os.path.join(GOLDEN, "requirements.txt")
    before = open(req, encoding="utf-8").read()

    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.4")

    assert vf["cve_cleared"] is True
    assert vf["from_version"] == "5.3.1"
    assert vf["to_version"] == "5.4"
    assert PYYAML_CVE in vf["target_cves"][0]["cve_or_vuln"]
    assert vf["target_cves"][0]["cleared"] is True
    assert vf["reanalysis"]["available"] is True
    assert vf["reanalysis"]["introduced"] == []
    assert vf["verdict"] == "fix_verified"
    # the upgrade diff touched the manifest in the scratch copy only
    assert "-PyYAML==5.3.1" in vf["manifest_diff"]
    assert "+PyYAML==5.4" in vf["manifest_diff"]
    # the ORIGINAL GOLDEN tree is byte-for-byte unchanged
    assert open(req, encoding="utf-8").read() == before
    assert "PyYAML==5.3.1" in open(req, encoding="utf-8").read()


def test_verify_fix_below_fix_not_cleared(mocked_db):
    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.3.2")
    assert vf["cve_cleared"] is False
    assert vf["target_cves"][0]["cleared"] is False
    assert vf["verdict"] == "cve_not_cleared"


def test_verify_fix_offline_has_no_baseline():
    # Offline the baseline scan sees NO findings, so verify_fix cannot know which
    # advisories apply -- it must NOT claim "cleared". (Regression: ``all([])``
    # used to make cve_cleared vacuously True.)
    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.4", offline=True)
    assert vf["cve_cleared"] is False
    assert vf["target_cves"] == []
    assert vf["verdict"] == "unverified_no_baseline"
    assert vf["reanalysis"]["available"] is False
    assert vf["verdict"] not in {"fix_verified", "cve_cleared_regressions_unknown"}


def test_verify_fix_baseline_outage_has_no_baseline(mocked_db, monkeypatch):
    # OSV is down for the FIRST (baseline) correlate only. The baseline then has
    # no findings, so nothing can be proven even though the after-scan succeeds.
    from scanner.correlate.osv import OsvNetworkError

    calls = {"n": 0}

    def _flaky(queries):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OsvNetworkError("simulated OSV outage during baseline")
        return [_IDS_BY_NAME.get(q["package"]["name"], []) for q in queries]

    monkeypatch.setattr(osv, "query_batch", _flaky)

    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:urllib3", version="1.25.9")
    assert vf["cve_cleared"] is False
    assert vf["verdict"] == "unverified_no_baseline"


def test_verify_fix_no_advisory_dep(mocked_db):
    # Flask has no mocked advisory, so the baseline finds no CVE on it: there is
    # nothing to clear, and we must not report it as cleared/verified.
    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:Flask", version="2.0.2")
    assert vf["cve_cleared"] is False
    assert vf["target_cves"] == []
    assert vf["verdict"] == "no_known_cves"


def test_verify_fix_prerelease_of_fixed_line_not_cleared(mocked_db):
    # Fix is 5.4; a pre-release of that same line (5.4b1) is NOT yet the fix.
    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.4b1")
    assert vf["target_cves"][0]["cleared"] is False
    assert vf["cve_cleared"] is False
    assert vf["verdict"] == "cve_not_cleared"


def test_verify_fix_prerelease_above_fixed_line_cleared(mocked_db):
    # A pre-release that is strictly above the fixed line (5.5b1 > 5.4) clears it.
    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.5b1")
    assert vf["target_cves"][0]["cleared"] is True
    assert vf["cve_cleared"] is True


def test_verify_fix_escalation_blocks_verified(mocked_db, monkeypatch):
    # An existing finding that goes reachable -> reachable+tainted (an exposure
    # escalation) must downgrade the verdict even though the target CVE clears.
    real = S._run_audit_pipeline
    calls = {"n": 0}

    def _escalating(repo_path, *, offline, use_nvd=False, refresh=False):
        calls["n"] += 1
        key, graph, corr, reach = real(
            repo_path, offline=offline, use_nvd=use_nvd, refresh=refresh
        )
        if calls["n"] == 2:  # the AFTER re-scan: escalate PyYAML to tainted
            for f in corr.findings:
                if f.dependency_id == "dep:PyPI:PyYAML":
                    f.taint = "tainted"
        return key, graph, corr, reach

    monkeypatch.setattr(S, "_run_audit_pipeline", _escalating)

    vf = _call(S.vscan_verify_fix, S.VerifyFixInput,
               repo_path=GOLDEN, dep_id="dep:PyPI:PyYAML", version="5.4")
    assert vf["cve_cleared"] is True          # version-math still clears the CVE
    assert vf["reanalysis"]["introduced"] == []  # escalation, not a new finding
    assert vf["reanalysis"]["changed"]           # the escalation is recorded
    assert vf["verdict"] == "fix_introduces_new_exposure"


def test_diff_pyyaml_upgrade_resolves_cve(mocked_db, monkeypatch, tmp_path):
    head = tmp_path / "golden-head"
    shutil.copytree(GOLDEN, head)
    req = head / "requirements.txt"
    req.write_text(req.read_text().replace("PyYAML==5.3.1", "PyYAML==5.4"))

    # OSV matches versions server-side; make the batch mock version-aware so the
    # upgraded head (PyYAML 5.4) no longer matches the advisory (fixed in 5.4),
    # while urllib3 (1.25.8) still does in both trees.
    _FIXED = {"PyYAML": "5.4", "urllib3": "1.26.5"}

    def _versioned_query(queries):
        out = []
        for q in queries:
            name = q["package"]["name"]
            ids = _IDS_BY_NAME.get(name, [])
            fixed = _FIXED.get(name)
            if ids and fixed and S.upgrade.version_key(q.get("version", "")) >= S.upgrade.version_key(fixed):
                ids = []
            out.append(ids)
        return out

    monkeypatch.setattr(osv, "query_batch", _versioned_query)

    df = _call(S.vscan_diff, S.DiffInput,
               repo_path_base=GOLDEN, repo_path_head=str(head))
    resolved_cves = {c for row in df["resolved"] for c in row["cve_ids"]}
    assert PYYAML_CVE in resolved_cves
    assert df["counts"]["resolved"] == 1
    assert df["counts"]["introduced"] == 0
    assert df["network_ok"] is True


def test_prompt_registered():
    names = {p.name for p in S.mcp._prompt_manager.list_prompts()}
    assert "audit_and_fix" in names
    text = S.audit_and_fix()
    assert isinstance(text, str) and text.strip()
    assert "vscan_verify_fix" in text


@pytest.fixture
def captured_run(monkeypatch):
    """Record ``mcp.run`` calls and restore the transport settings afterwards."""
    for field in ("host", "port", "transport_security"):
        monkeypatch.setattr(S.mcp.settings, field, getattr(S.mcp.settings, field))
    calls = []
    monkeypatch.setattr(S.mcp, "run", lambda transport: calls.append(transport))
    return calls


def test_main_defaults_to_stdio(captured_run):
    S.main([])
    assert captured_run == ["stdio"]


def test_main_http_on_public_bind_drops_localhost_host_check(captured_run):
    assert S.mcp.settings.transport_security is not None  # loopback default
    S.main(["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9000"])
    assert captured_run == ["streamable-http"]
    assert (S.mcp.settings.host, S.mcp.settings.port) == ("0.0.0.0", 9000)
    assert S.mcp.settings.transport_security is None


def test_main_http_on_loopback_keeps_host_check(captured_run):
    S.main(["--transport", "streamable-http"])
    assert S.mcp.settings.transport_security is not None
