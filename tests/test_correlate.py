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

from scanner.correlate import CorrelationResult, Finding, correlate, correlate_full
from scanner.correlate import cache, enrich, osv, report
from scanner.graph import KnowledgeGraph
from scanner.reachability import (
    POTENTIALLY_REACHABLE,
    ReachabilityResult,
    compute_reachability,
)
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
        "details": (
            "The package PyYAML before 5.3.1 is vulnerable to Arbitrary Code "
            "Execution. When using the full_load method or the FullLoader loader, "
            "a crafted YAML file naming python/object/new tags can be abused. The "
            "yaml.load function with the default loader is the vulnerable sink."
        ),
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


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Point the on-disk cache at a fresh temp dir for every test.

    OSV vuln records are now cached (``osv-vuln:<id>``, 7-day TTL). Without this
    redirect the suite would read/write the user's real ``~/.cache/vulnreach``,
    leaking fixtures across runs and making call-count assertions non-hermetic.
    Tests that set ``VULNREACH_CACHE_DIR`` themselves simply override this.
    """
    monkeypatch.setenv("VULNREACH_CACHE_DIR", str(tmp_path / "vulnreach-cache"))


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


def test_finding_carries_full_osv_details(graph, mocked_db):
    # The one-line title stays in `summary`; the full OSV `details` description
    # (which names the vulnerable sink) is carried through onto the Finding.
    findings = correlate(graph)
    pyyaml = _find(findings, "PyYAML")

    assert pyyaml.summary and "yaml.load" not in pyyaml.summary
    assert pyyaml.details is not None
    assert "yaml.load" in pyyaml.details


def test_audit_payload_includes_finding_details(graph, mocked_db):
    # The serialized audit payload (bundle/--json) exposes `details` so a UI can
    # show the real CVE description, not just the one-line title.
    result = correlate_full(graph)
    reach = compute_reachability(graph)
    payload = report.audit(graph, result, reach)

    pyyaml = next(f for f in payload["findings"] if f["dependency_name"] == "PyYAML")
    assert "details" in pyyaml
    assert pyyaml["details"] and "yaml.load" in pyyaml["details"]


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


# #13 -- vuln records are cached on disk: a warm run makes zero network fetches.


def test_collect_caches_vuln_records(monkeypatch):
    # query_batch resolves two deps to two distinct vuln ids; fetch_vuln is the
    # single network seam. The first collect() populates the cache; the second,
    # for the same ids, must be served entirely from disk -- zero fetches.
    def fake_query_batch(queries):
        return [["GHSA-aaaa"], ["GHSA-bbbb"]]

    calls: list[str] = []

    def counting_fetch(vuln_id):
        calls.append(vuln_id)
        return {
            "id": vuln_id,
            "summary": f"advisory {vuln_id}",
            "affected": [{"package": {"name": "pkg", "ecosystem": "npm"}}],
        }

    monkeypatch.setattr(osv, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv, "fetch_vuln", counting_fetch)

    deps = [
        osv.DepRef(id="d1", name="a", version="1.0.0", ecosystem="npm"),
        osv.DepRef(id="d2", name="b", version="2.0.0", ecosystem="npm"),
    ]

    cold = osv.collect(deps)
    assert cold.ok is True
    assert sorted(calls) == ["GHSA-aaaa", "GHSA-bbbb"]  # each id fetched once

    calls.clear()
    warm = osv.collect(deps)
    assert warm.ok is True
    assert calls == []  # fully served from the disk cache -- zero network calls
    # Warm result is identical in content to the cold one.
    assert warm.by_dep.keys() == cold.by_dep.keys()


def test_collect_maps_each_id_to_its_own_record(monkeypatch):
    # With parallel fetches completing out of order, every id must still map to
    # its OWN record -- no cross-assignment from the thread pool.
    import time

    n = 12
    ids = [f"GHSA-{i:04d}" for i in range(n)]

    def fake_query_batch(queries):
        # One dep per query, each resolving to its own unique vuln id.
        return [[ids[i]] for i in range(len(queries))]

    def fake_fetch(vuln_id):
        # Reverse-index sleep so later ids finish first -> scramble completion.
        idx = int(vuln_id.split("-")[1])
        time.sleep(0.002 * (n - idx))
        return {
            "id": vuln_id,
            "summary": f"advisory {vuln_id}",
            "affected": [{"package": {"name": f"pkg{idx}", "ecosystem": "npm"}}],
        }

    monkeypatch.setattr(osv, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv, "fetch_vuln", fake_fetch)

    deps = [
        osv.DepRef(id=f"dep{i}", name=f"pkg{i}", version="1.0.0", ecosystem="npm")
        for i in range(n)
    ]
    result = osv.collect(deps)
    assert result.ok is True
    assert set(result.by_dep.keys()) == {f"dep{i}" for i in range(n)}
    # Each dependency's advisory id must be exactly its own, never a neighbour's.
    for i in range(n):
        vulns = result.by_dep[f"dep{i}"]
        assert [v.id for v in vulns] == [ids[i]]


def test_collect_degrades_when_a_parallel_fetch_fails(monkeypatch):
    # One fetch raising mid-pool must degrade to ok=False, never propagate.
    def fake_query_batch(queries):
        return [["GHSA-aaaa"], ["GHSA-bbbb"], ["GHSA-cccc"]]

    def flaky_fetch(vuln_id):
        if vuln_id == "GHSA-bbbb":
            raise osv.OsvNetworkError("simulated vuln fetch outage")
        return {"id": vuln_id, "summary": "ok", "affected": []}

    monkeypatch.setattr(osv, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv, "fetch_vuln", flaky_fetch)

    deps = [
        osv.DepRef(id="d1", name="a", version="1.0.0", ecosystem="npm"),
        osv.DepRef(id="d2", name="b", version="2.0.0", ecosystem="npm"),
        osv.DepRef(id="d3", name="c", version="3.0.0", ecosystem="npm"),
    ]
    result = osv.collect(deps)  # must not raise
    assert result.ok is False
    assert result.by_dep == {}


def test_collect_degrades_on_unexpected_worker_exception(monkeypatch):
    # A non-network exception in a worker must also be caught and degraded,
    # never propagated as a new exception type into the caller/CLI.
    def fake_query_batch(queries):
        return [["GHSA-aaaa"]]

    def boom_fetch(vuln_id):
        raise ValueError("unexpected worker crash")

    monkeypatch.setattr(osv, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv, "fetch_vuln", boom_fetch)

    deps = [osv.DepRef(id="d1", name="a", version="1.0.0", ecosystem="npm")]
    result = osv.collect(deps)  # must not raise ValueError
    assert result.ok is False
    assert result.by_dep == {}


# #14 -- A1: the audit JSON must NOT re-derive a confident ``unreachable`` from
# the binary ``finding.reachable`` when the dep id is absent from
# ``verdict_by_dep`` (whose four-part gate is the only sound source of that label).


def test_audit_verdict_defaults_to_potentially_reachable_when_absent():
    ghost = Finding(
        dependency_id="dep:ghost-not-in-verdict-map",
        dependency_name="ghost",
        version="1.0.0",
        ecosystem="PyPI",
        vuln_id="GHSA-ghost",
        cve_ids=["CVE-2099-0001"],
        summary="",
        fixed_versions=[],
    )
    assert ghost.reachable is False
    correlation = CorrelationResult(findings=[ghost], offline=False, network_ok=True)
    reach = ReachabilityResult()  # empty repo roll-up -> verdict_by_dep == {}
    assert ghost.dependency_id not in reach.repo.verdict_by_dep

    payload = report.audit(KnowledgeGraph(), correlation, reach)

    serialized = next(
        f
        for f in payload["findings"]
        if f["dependency_id"] == "dep:ghost-not-in-verdict-map"
    )
    # Conservative default -- never the confident (and here unsound) ``unreachable``.
    assert serialized["verdict"] == POTENTIALLY_REACHABLE
    assert serialized["verdict"] != "unreachable"


# #15 -- T2: cache round-trip, TTL expiry (with stale-file cleanup) and fail-soft
# on a corrupt entry. The autouse ``_isolated_cache`` fixture already points
# VULNREACH_CACHE_DIR at a fresh temp dir for every test.


def test_cache_round_trip_returns_stored_value():
    cache.set("rt-key", {"a": 1, "b": [2, 3]}, ttl=100)
    assert cache.get("rt-key") == {"a": 1, "b": [2, 3]}


def test_cache_get_expires_and_unlinks_stale_file():
    cache.set("exp-key", {"v": 1}, ttl=-1)  # expires in the past
    path = cache._path_for("exp-key")
    assert path.exists()  # the entry was actually written
    # A past TTL must read as a miss AND remove the stale file.
    assert cache.get("exp-key") is None
    assert not path.exists()


def test_cache_get_on_corrupt_file_is_a_miss():
    path = cache._path_for("corrupt-key")  # also creates the cache dir
    path.write_text("{ this is not valid json ", encoding="utf-8")
    # A garbage entry must fail soft -- a miss, never a raise.
    assert cache.get("corrupt-key") is None


# -- symbol-level advisory matching (symbol_match) ----------------------------
#
# A deterministic, always-on 3-tier signal derived FROM the resolved
# reachability verdict: "confirmed" (the advisory's named function is among the
# dep's reached symbols), "no_path" (verdict unreachable), or "package_reachable"
# (reachable but the specific vulnerable function is unconfirmed). It must never
# change `reachable`, the verdict, ranking, or the existing summary counts.

from scanner.reachability import (  # noqa: E402 -- grouped with the feature's tests
    REACHABLE,
    UNREACHABLE,
    EntrypointReachability,
    ReachedDependency,
    RepoReachability,
)

_SYM_DEP = "dep:PyPI:PyYAML"


def _reach_with(symbols, verdict):
    """A minimal ReachabilityResult: one entry point reaching ``_SYM_DEP``.

    ``verdict`` is stored in ``repo.verdict_by_dep``; the dep is listed as
    reachable only when its verdict is not ``unreachable`` (so the reachable-set
    and verdict layers stay consistent, as the real engine keeps them).
    """
    reachable = verdict != UNREACHABLE
    ep = EntrypointReachability(
        id="ep:POST:/import",
        method="POST",
        path="/import",
        handlers=["fn:app.py:do_import"],
        reachable_function_count=1,
        reachable_dependencies=(
            [
                ReachedDependency(
                    id=_SYM_DEP,
                    name="PyYAML",
                    version="5.3",
                    ecosystem="PyPI",
                    symbol=symbols[0] if symbols else None,
                    symbols=list(symbols),
                    example_path=["ep:POST:/import", _SYM_DEP],
                )
            ]
            if reachable
            else []
        ),
        unresolved_calls_encountered=0,
    )
    repo = RepoReachability(
        reachable_deps=[{"id": _SYM_DEP}] if reachable else [],
        verdict_by_dep={_SYM_DEP: verdict},
    )
    return ReachabilityResult(entrypoints=[ep], repo=repo)


def _sym_finding(summary, details):
    return Finding(
        dependency_id=_SYM_DEP,
        dependency_name="PyYAML",
        version="5.3",
        ecosystem="PyPI",
        vuln_id="GHSA-pyyaml-3pqx",
        cve_ids=[PYYAML_CVE],
        summary=summary,
        fixed_versions=["5.3.1"],
        details=details,
    )


def test_symbol_match_confirmed_when_named_function_is_reached():
    # The advisory names ``yaml.load`` and the dep is reached via ``yaml.load``.
    finding = _sym_finding(
        "PyYAML code execution", "The yaml.load function is the vulnerable sink."
    )
    report.join_reachability(
        KnowledgeGraph(), [finding], _reach_with(["yaml.load"], REACHABLE)
    )

    assert finding.reachable is True
    assert finding.reached_symbols == ["yaml.load"]
    assert finding.symbol_match == "confirmed"


def test_symbol_match_package_reachable_when_named_function_not_reached():
    # The advisory names ``full_load`` but the project only calls ``safe_load``:
    # reachable package, but the specific vulnerable function is unconfirmed.
    finding = _sym_finding("PyYAML code execution", "The full_load method is vulnerable.")
    report.join_reachability(
        KnowledgeGraph(), [finding], _reach_with(["yaml.safe_load"], REACHABLE)
    )

    assert finding.reachable is True
    assert finding.reached_symbols == ["yaml.safe_load"]
    assert finding.symbol_match == "package_reachable"


def test_symbol_match_package_reachable_when_advisory_names_no_function():
    # The advisory names no specific function (a generic/transitive description):
    # still a live finding, never silently "safe".
    finding = _sym_finding(
        "PyYAML allows arbitrary code execution",
        "Parsing untrusted input can lead to arbitrary code execution.",
    )
    report.join_reachability(
        KnowledgeGraph(), [finding], _reach_with(["yaml.safe_load"], REACHABLE)
    )

    assert finding.reachable is True
    assert finding.symbol_match == "package_reachable"


def test_symbol_match_no_path_when_verdict_unreachable():
    # The dep's resolved verdict is ``unreachable`` -- the only tier-2 case, and
    # sound because verdict_by_dep already applied the fully-resolved gate.
    finding = _sym_finding(
        "PyYAML code execution", "The yaml.load function is the vulnerable sink."
    )
    report.join_reachability(
        KnowledgeGraph(), [finding], _reach_with(["yaml.load"], UNREACHABLE)
    )

    assert finding.reachable is False
    assert finding.symbol_match == "no_path"


def test_build_summary_counts_symbol_confirmed():
    confirmed = _sym_finding("PyYAML", "The yaml.load function is vulnerable.")
    report.join_reachability(
        KnowledgeGraph(), [confirmed], _reach_with(["yaml.load"], REACHABLE)
    )

    pkg = _sym_finding("PyYAML", "The full_load method is vulnerable.")
    report.join_reachability(
        KnowledgeGraph(), [pkg], _reach_with(["yaml.safe_load"], REACHABLE)
    )

    none = _sym_finding("lodash prototype pollution", "Prototype pollution via merge.")
    none.dependency_id = "dep:npm:lodash"
    none.dependency_name = "lodash"
    report.join_reachability(KnowledgeGraph(), [none], ReachabilityResult())

    assert confirmed.symbol_match == "confirmed"
    assert pkg.symbol_match == "package_reachable"
    summary = report.build_summary(KnowledgeGraph(), [confirmed, pkg, none])
    assert summary["symbol_confirmed_vulnerabilities"] == 1
