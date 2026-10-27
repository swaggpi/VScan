"""Correlator tests -- MUST NOT touch the network.

The graph comes from the real, deterministic, offline ``scan_repo`` over
``samples/vulnerable-app``. Only the vulnerability-database calls are mocked:
the OSV ``query_batch`` / ``fetch_vuln`` boundary and the enrichment
``fetch_kev_catalog`` / ``query_epss`` boundary are monkeypatched to return
small recorded fixtures, so parsing, the reachability join, ranking and the
graceful-offline path are all exercised without any real request.
"""

from __future__ import annotations

import os

import pytest

from scanner.correlate import Finding, correlate, correlate_full
from scanner.correlate import cache, enrich, osv, report
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)

PYYAML_CVE = "CVE-2020-1747"
LODASH_CVE = "CVE-2019-10744"

# Recorded (abridged) OSV full records, shaped exactly like /v1/vulns/{id}.
_OSV_RECORDS = {
    "GHSA-pyyaml-3pqx": {
        "id": "GHSA-pyyaml-3pqx",
        "summary": "PyYAML full_load / load allows arbitrary code execution",
        "aliases": [PYYAML_CVE, "PYSEC-2020-176"],
        "database_specific": {"severity": "CRITICAL"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}
                ],
            }
        ],
    },
    "GHSA-lodash-p6mc": {
        "id": "GHSA-lodash-p6mc",
        "summary": "Prototype pollution in lodash",
        "aliases": [LODASH_CVE],
        "database_specific": {"severity": "HIGH"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}
        ],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.11"}]}
                ],
            }
        ],
    },
}

# Which recorded ids each queried package resolves to in querybatch.
_OSV_IDS_BY_NAME = {
    "PyYAML": ["GHSA-pyyaml-3pqx"],
    "lodash": ["GHSA-lodash-p6mc"],
    # Jinja2 is our clean dependency: it resolves to no advisories.
    "Jinja2": [],
}

_KEV_SET = {PYYAML_CVE}  # PyYAML is actively exploited; lodash is not.

_EPSS = {
    PYYAML_CVE: (0.92, 0.99),
    LODASH_CVE: (0.10, 0.45),
}


@pytest.fixture
def mocked_db(monkeypatch):
    """Patch every network boundary with the recorded fixtures above."""

    def fake_query_batch(queries):
        return [_OSV_IDS_BY_NAME.get(q["package"]["name"], []) for q in queries]

    def fake_fetch_vuln(vuln_id):
        return _OSV_RECORDS[vuln_id]

    monkeypatch.setattr(osv, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv, "fetch_vuln", fake_fetch_vuln)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: set(_KEV_SET))
    monkeypatch.setattr(enrich, "query_epss", lambda cves: dict(_EPSS))


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


def _find(findings, dep_name):
    return next(f for f in findings if f.dependency_name == dep_name)


def test_finding_produced_with_cve_and_fixed_version(graph, mocked_db):
    findings = correlate(graph)
    pyyaml = _find(findings, "PyYAML")

    assert pyyaml.version == "3.13"
    assert pyyaml.ecosystem == "PyPI"
    assert PYYAML_CVE in pyyaml.cve_ids
    assert "5.3.1" in pyyaml.fixed_versions
    assert pyyaml.severity == "CRITICAL"
    # No numeric score without NVD, but the OSV vector is carried.
    assert pyyaml.cvss_score is None
    assert pyyaml.cvss_vector and pyyaml.cvss_source == "OSV"


def test_clean_dependency_produces_no_finding(graph, mocked_db):
    findings = correlate(graph)
    assert all(f.dependency_name != "Jinja2" for f in findings)


def test_kev_and_epss_attach_from_enrichment(graph, mocked_db):
    findings = correlate(graph)
    pyyaml = _find(findings, "PyYAML")
    lodash = _find(findings, "lodash")

    assert pyyaml.kev is True
    assert pyyaml.epss == pytest.approx(0.92)
    assert pyyaml.epss_percentile == pytest.approx(0.99)

    assert lodash.kev is False
    assert lodash.epss == pytest.approx(0.10)


def test_reachability_join_marks_reachable_and_unreachable(graph, mocked_db):
    findings = correlate(graph)
    reach = compute_reachability(graph)
    report.join_reachability(graph, findings, reach)

    pyyaml = _find(findings, "PyYAML")
    lodash = _find(findings, "lodash")

    assert pyyaml.reachable is True
    assert "POST /import" in pyyaml.reachable_entrypoints
    assert pyyaml.example_path and pyyaml.example_path[0] == "ep:POST:/import"

    # lodash is declared (frontend) but never called from an entry point.
    assert lodash.reachable is False
    assert lodash.reachable_entrypoints == []


def test_ranking_puts_kev_reachable_first(graph, mocked_db):
    findings = correlate(graph)
    reach = compute_reachability(graph)
    report.join_reachability(graph, findings, reach)
    ranked = report.rank_findings(findings)

    names = [f.dependency_name for f in ranked]
    # PyYAML is KEV + reachable; lodash is neither -> PyYAML ranks strictly higher.
    assert names.index("PyYAML") < names.index("lodash")
    assert ranked[0].dependency_name == "PyYAML"


def test_summary_counts(graph, mocked_db):
    findings = correlate(graph)
    reach = compute_reachability(graph)
    report.join_reachability(graph, findings, reach)
    summary = report.build_summary(graph, findings)

    assert summary["total_vulnerabilities"] == 2
    assert summary["vulnerable_dependencies"] == 2
    assert summary["reachable_vulnerabilities"] == 1  # PyYAML only
    assert summary["kev_vulnerabilities"] == 1
    assert summary["high_epss_vulnerabilities"] == 1  # PyYAML epss 0.92 >= 0.5


def test_alias_linked_advisories_are_deduped():
    # Same flaw surfaced as a GHSA record and a PYSEC/CVE record (OSV does this
    # routinely). They share a CVE alias and must collapse into one OsvVuln.
    ghsa = osv.OsvVuln(
        id="GHSA-xxxx",
        cve_ids=["CVE-2020-1747"],
        summary="PyYAML code execution",
        severity_label="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixed_versions=["5.3.1"],
    )
    pysec = osv.OsvVuln(
        id="PYSEC-2020-176",
        cve_ids=["CVE-2020-1747"],
        summary="",
        severity_label=None,
        cvss_vector=None,
        fixed_versions=["5.3.1"],
    )
    other = osv.OsvVuln(
        id="GHSA-yyyy",
        cve_ids=["CVE-2019-20477"],
        summary="different flaw",
        severity_label="HIGH",
        cvss_vector=None,
        fixed_versions=["5.2"],
    )

    merged = osv.merge_vulns([ghsa, pysec, other])
    assert len(merged) == 2
    big = next(m for m in merged if "CVE-2020-1747" in m.cve_ids)
    # The richer GHSA record wins severity/vector; fixed versions are unioned.
    assert big.severity_label == "CRITICAL"
    assert big.cvss_vector
    assert big.fixed_versions == ["5.3.1"]


def test_offline_returns_empty_without_raising(graph):
    # No mocks installed: offline must not attempt (or need) the network.
    result = correlate_full(graph, offline=True)
    assert result.findings == []
    assert result.offline is True
    assert result.network_ok is False
    assert result.notices  # a graceful notice is set

    assert correlate(graph, offline=True) == []


def test_osv_network_failure_degrades_gracefully(graph, monkeypatch):
    def boom(_queries):
        raise osv.OsvNetworkError("simulated outage")

    monkeypatch.setattr(osv, "query_batch", boom)
    result = correlate_full(graph)
    assert result.findings == []
    assert result.network_ok is False
    assert result.notices


def test_cli_offline_prints_graceful_message(capsys):
    from scanner.cli import main

    rc = main(["audit", SAMPLE_APP, "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Offline mode" in out
    # Reachability is still shown offline.
    assert "Reachability" in out
    assert "PyYAML" in out


def test_cli_bundle_is_self_contained(tmp_path):
    """``--bundle`` writes one JSON the viewer can load, without changing output.

    Runs offline (no network) so it stays fast and deterministic: findings are
    empty, but the graph, reachability and summary must still be present and the
    offline status flagged honestly.
    """
    import json

    from scanner.cli import main

    bundle_path = tmp_path / "bundle.json"
    rc = main(["audit", SAMPLE_APP, "--offline", "--bundle", str(bundle_path)])
    assert rc == 0

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    # All four sections the viewer needs are present.
    assert set(["graph", "reachability", "findings", "summary"]).issubset(bundle)
    assert isinstance(bundle["graph"]["nodes"], list) and bundle["graph"]["nodes"]
    assert "entrypoints" in bundle["reachability"]
    assert "repo" in bundle["reachability"]
    # Offline run: honest status, empty findings, but structure still present.
    assert bundle["offline"] is True
    assert bundle["findings"] == []
    assert bundle["summary"]["total_dependencies"] >= 1


# -- regression tests for reproduced correctness/robustness bugs --------------


class _FakeResp:
    """Minimal urlopen() context-manager stub returning canned bytes."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *exc) -> bool:
        return False


# #8 -- querybatch length misalignment must never cross-attribute a vuln.


def test_querybatch_length_mismatch_raises(monkeypatch):
    # A short response for a 2-query chunk must raise rather than silently map
    # the ids onto the wrong queries (and shift every later chunk).
    monkeypatch.setattr(osv, "_post_json", lambda url, body: {"results": []})
    with pytest.raises(osv.OsvNetworkError):
        osv.query_batch(
            [
                {"package": {"name": "a", "ecosystem": "npm"}, "version": "1.0.0"},
                {"package": {"name": "b", "ecosystem": "npm"}, "version": "2.0.0"},
            ]
        )


def test_collect_degrades_on_querybatch_mismatch(monkeypatch):
    # One result slot for two queries: collect must degrade (ok=False, empty),
    # never attribute the lone (fully fetchable) vuln id to the wrong DepRef.
    # fetch_vuln is mocked so that, without the length guard, the bug would
    # surface as a successful-but-misattributed result rather than a network
    # failure -- isolating the cross-attribution this test defends against.
    monkeypatch.setattr(
        osv, "_post_json", lambda url, body: {"results": [{"vulns": [{"id": "GHSA-x"}]}]}
    )
    monkeypatch.setattr(
        osv,
        "fetch_vuln",
        lambda vuln_id: {
            "id": "GHSA-x",
            "summary": "misattributable advisory",
            "affected": [{"package": {"name": "a", "ecosystem": "npm"}}],
        },
    )
    deps = [
        osv.DepRef(id="d1", name="a", version="1.0.0", ecosystem="npm"),
        osv.DepRef(id="d2", name="b", version="2.0.0", ecosystem="npm"),
    ]
    result = osv.collect(deps)
    assert result.ok is False
    assert result.by_dep == {}


# #7 -- the "never raises" contract holds on malformed (non-dict) JSON.


def test_post_json_rejects_non_dict(monkeypatch):
    monkeypatch.setattr(osv.urllib.request, "urlopen", lambda *a, **k: _FakeResp(b"[]"))
    with pytest.raises(osv.OsvNetworkError):
        osv._post_json("https://example.invalid", {})


def test_get_json_rejects_non_dict(monkeypatch):
    monkeypatch.setattr(
        osv.urllib.request, "urlopen", lambda *a, **k: _FakeResp(b"\"a string\"")
    )
    with pytest.raises(osv.OsvNetworkError):
        osv._get_json("https://example.invalid")


def test_correlate_full_degrades_on_non_dict_batch(graph, monkeypatch):
    # A list payload from querybatch must degrade gracefully, not crash the CLI
    # with an AttributeError.
    monkeypatch.setattr(osv.urllib.request, "urlopen", lambda *a, **k: _FakeResp(b"[]"))
    result = correlate_full(graph)
    assert result.network_ok is False
    assert result.findings == []
    assert result.notices


def test_kev_rejects_non_dict(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNREACH_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(enrich, "_get", lambda url, headers=None: b"[]")
    with pytest.raises(enrich.EnrichNetworkError):
        enrich.fetch_kev_catalog()


def test_enrich_findings_never_raises_on_non_dict(tmp_path, monkeypatch):
    # Both KEV and EPSS returning a non-dict JSON must degrade to notices, never
    # raise out of enrich_findings.
    monkeypatch.setenv("VULNREACH_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(enrich, "_get", lambda url, headers=None: b"[]")
    finding = Finding(
        dependency_id="d",
        dependency_name="x",
        version="1",
        ecosystem="npm",
        vuln_id="GHSA",
        cve_ids=[PYYAML_CVE],
        summary="",
        fixed_versions=[],
    )
    notices = enrich.enrich_findings([finding], use_nvd=False)
    assert any("KEV" in n for n in notices)
    assert any("EPSS" in n for n in notices)


# #9 -- _fixed_versions must not leak other packages' fixes or GIT commit hashes.


def test_fixed_versions_ignores_other_packages_and_git():
    record = {
        "id": "GHSA-z",
        "affected": [
            {  # unrelated package -- its fix must never be reported.
                "package": {"name": "other-pkg", "ecosystem": "npm"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
                ],
            },
            {  # our package but a GIT range -- a commit hash, never a version.
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "deadbeefcafe0001"}]}
                ],
            },
        ],
    }
    assert osv._fixed_versions(record, "lodash", "npm") == []


def test_fixed_versions_reads_matching_version_range():
    record = {
        "id": "GHSA-ok",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.11"}]}],
            }
        ],
    }
    assert osv._fixed_versions(record, "lodash", "npm") == ["4.17.11"]


# #10 -- cache must fail soft when its directory cannot be created.


def test_cache_fails_soft_on_uncreatable_dir(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setenv("VULNREACH_CACHE_DIR", str(blocker / "sub"))
    assert cache.get("some-key") is None  # no raise
    cache.set("some-key", {"value": 1}, ttl=100)  # no raise
    assert cache.get("some-key") is None


# #11 -- non-concrete versions must be surfaced, not silently dropped.


def test_skipped_non_concrete_versions_recorded(mocked_db):
    deps = [
        osv.DepRef(id="d1", name="lodash", version="^4.17.4", ecosystem="npm"),
        osv.DepRef(id="d2", name="PyYAML", version="3.13", ecosystem="PyPI"),
    ]
    result = osv.collect(deps)
    assert any("lodash" in s and "^4.17.4" in s for s in result.skipped)


def test_caret_dependency_surfaced_in_notices(graph, mocked_db):
    # The sample app declares ``requests>=2.20.0`` -- a range, not an exact pin.
    # It must appear in a notice rather than being silently treated as clean.
    result = correlate_full(graph)
    assert any("no exact version" in n for n in result.notices)
    assert any("requests" in n for n in result.notices)


# #12 -- the three-way verdict must be exposed in the audit JSON payload.


def test_audit_json_exposes_three_way_verdict(graph, mocked_db):
    result = correlate_full(graph)
    reach = compute_reachability(graph)
    payload = report.audit(graph, result, reach)

    valid = {"reachable", "potentially_reachable", "unreachable"}
    assert payload["findings"]
    for finding in payload["findings"]:
        assert finding["verdict"] in valid

    pyyaml = next(f for f in payload["findings"] if f["dependency_name"] == "PyYAML")
    assert pyyaml["verdict"] == "reachable"
