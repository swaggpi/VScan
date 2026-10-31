"""Tier-2 output tests: SARIF 2.1.0, the impact funnel, exit codes, markdown.

All offline and deterministic. SARIF/markdown are exercised against hand-built
payload dicts (the pure-formatter path) plus a small graph that carries the
dependency manifest ``source_file``; the funnel and exit codes are exercised
through the real ``format_report`` / CLI paths so defaults stay verified.
"""

from __future__ import annotations

from scanner.cli import _compute_exit_code, main
from scanner.correlate import CorrelationResult, Finding
from scanner.correlate import report
from scanner.correlate.sarif import to_markdown, to_sarif
from scanner.graph import KnowledgeGraph
from scanner.reachability import (
    REACHABLE,
    UNREACHABLE,
    EntrypointReachability,
    ReachabilityResult,
    ReachedDependency,
    RepoReachability,
)
from scanner.taint import TaintResult


# --------------------------------------------------------------------------
# Payload / graph builders for the pure formatters.
# --------------------------------------------------------------------------


def _finding_dict(**overrides):
    base = {
        "dependency_id": "dep:PyPI:pkg",
        "dependency_name": "pkg",
        "version": "1.0.0",
        "ecosystem": "PyPI",
        "vuln_id": "GHSA-xxxx",
        "cve_ids": ["CVE-2020-0001"],
        "summary": "A vulnerability",
        "details": "The vulnerable_fn sink is the problem.",
        "fixed_versions": ["1.0.1"],
        "severity": "HIGH",
        "cvss_score": None,
        "reachable": False,
        "symbol_match": "no_path",
        "taint": "not_proven",
        "example_path": [],
        "verdict": UNREACHABLE,
    }
    base.update(overrides)
    return base


def _graph_with_deps(dep_sources):
    """A graph with one dependency node per ``{dep_id: source_file}`` entry."""
    graph = KnowledgeGraph()
    for dep_id, source_file in dep_sources.items():
        attrs = {}
        if source_file is not None:
            attrs["source_file"] = source_file
        graph.add_node(dep_id, "dependency", dep_id, **attrs)
    return graph


def _four_finding_payload():
    """Four findings exercising every SARIF level + a shared CVE (one rule)."""
    f_tainted = _finding_dict(
        dependency_id="dep:PyPI:alpha",
        dependency_name="alpha",
        version="1.2.3",
        cve_ids=["CVE-2020-1747"],
        vuln_id="GHSA-alpha",
        summary="alpha RCE",
        cvss_score=9.8,
        reachable=True,
        symbol_match="confirmed",
        taint="tainted",
        verdict=REACHABLE,
        example_path=["ep:POST:/x", "dep:PyPI:alpha"],
    )
    f_confirmed = _finding_dict(
        dependency_id="dep:npm:beta",
        dependency_name="beta",
        version="4.0.0",
        ecosystem="npm",
        cve_ids=["CVE-2019-10744"],
        vuln_id="GHSA-beta",
        summary="beta prototype pollution",
        cvss_score=None,
        reachable=True,
        symbol_match="confirmed",
        taint="not_proven",
        verdict=REACHABLE,
    )
    # Same CVE as f_confirmed, different dependency -> still ONE rule.
    f_reachable = _finding_dict(
        dependency_id="dep:npm:gamma",
        dependency_name="gamma",
        version="2.0.0",
        ecosystem="npm",
        cve_ids=["CVE-2019-10744"],
        vuln_id="GHSA-gamma",
        summary="gamma prototype pollution",
        reachable=True,
        symbol_match="package_reachable",
        taint="not_proven",
        verdict=REACHABLE,
    )
    f_unreachable = _finding_dict(
        dependency_id="dep:PyPI:delta",
        dependency_name="delta",
        version="0.1.0",
        cve_ids=[],  # no CVE -> rule id falls back to vuln_id
        vuln_id="GHSA-delta",
        summary="delta issue",
        reachable=False,
        symbol_match="no_path",
        verdict=UNREACHABLE,
    )
    findings = [f_tainted, f_confirmed, f_reachable, f_unreachable]
    summary = {
        "total_dependencies": 4,
        "vulnerable_dependencies": 4,
        "total_vulnerabilities": 4,
        "reachable_vulnerabilities": 3,
        "symbol_confirmed_vulnerabilities": 2,
        "kev_vulnerabilities": 0,
        "high_epss_vulnerabilities": 0,
        "taint_confirmed_vulnerabilities": 1,
    }
    payload = {"summary": summary, "findings": findings}
    graph = _graph_with_deps(
        {
            "dep:PyPI:alpha": "requirements.txt",
            "dep:npm:beta": "package.json",
            "dep:npm:gamma": "package.json",
            "dep:PyPI:delta": None,  # no manifest -> placeholder
        }
    )
    return payload, graph


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def test_sarif_top_level_shape():
    payload, graph = _four_finding_payload()
    log = to_sarif(payload, graph)

    assert log["version"] == "2.1.0"
    assert "$schema" in log and log["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "VScan"
    assert driver["informationUri"].startswith("http")
    assert isinstance(driver["rules"], list)
    assert isinstance(log["runs"][0]["results"], list)


def test_sarif_one_rule_per_unique_cve():
    payload, graph = _four_finding_payload()
    log = to_sarif(payload, graph)
    rule_ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]

    # Four findings, but f_confirmed/f_reachable share CVE-2019-10744 -> 3 rules.
    assert rule_ids == ["CVE-2019-10744", "CVE-2020-1747", "GHSA-delta"]
    assert len(log["runs"][0]["results"]) == 4


def test_sarif_level_mapping():
    payload, graph = _four_finding_payload()
    results = to_sarif(payload, graph)["runs"][0]["results"]
    by_fp = {
        r["partialFingerprints"]["vscan/v1"]: r["level"] for r in results
    }

    assert by_fp["dep:PyPI:alpha|GHSA-alpha"] == "error"  # tainted
    assert by_fp["dep:npm:beta|GHSA-beta"] == "warning"  # confirmed
    assert by_fp["dep:npm:gamma|GHSA-gamma"] == "warning"  # reachable only
    assert by_fp["dep:PyPI:delta|GHSA-delta"] == "note"  # unreachable


def test_sarif_location_uri_is_the_manifest_file():
    payload, graph = _four_finding_payload()
    results = to_sarif(payload, graph)["runs"][0]["results"]
    uri_by_fp = {
        r["partialFingerprints"]["vscan/v1"]: r["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"]
        for r in results
    }

    assert uri_by_fp["dep:PyPI:alpha|GHSA-alpha"] == "requirements.txt"
    assert uri_by_fp["dep:npm:beta|GHSA-beta"] == "package.json"
    # No manifest -> a repo-relative placeholder, never missing.
    assert uri_by_fp["dep:PyPI:delta|GHSA-delta"] == "dependency-manifest"
    for r in results:
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_security_severity_present_only_with_cvss():
    payload, graph = _four_finding_payload()
    rules = {r["id"]: r for r in to_sarif(payload, graph)["runs"][0]["tool"]["driver"]["rules"]}

    # CVE-2020-1747 carried cvss_score 9.8 -> numeric security-severity string.
    assert rules["CVE-2020-1747"]["properties"]["security-severity"] == "9.8"
    # CVE-2019-10744 had no numeric CVSS -> no properties / security-severity.
    assert "properties" not in rules["CVE-2019-10744"]


def test_sarif_ordering_is_stable():
    payload, graph = _four_finding_payload()
    log_a = to_sarif(payload, graph)
    # Reverse the findings order; output must be identical (deterministic sort).
    payload_b = {"summary": payload["summary"], "findings": list(reversed(payload["findings"]))}
    log_b = to_sarif(payload_b, graph)
    assert log_a == log_b


def test_sarif_rule_carries_details_as_help_and_full_description():
    payload, graph = _four_finding_payload()
    rules = {r["id"]: r for r in to_sarif(payload, graph)["runs"][0]["tool"]["driver"]["rules"]}
    rule = rules["CVE-2020-1747"]
    assert rule["shortDescription"]["text"] == "alpha RCE"
    assert "sink" in rule["fullDescription"]["text"]
    assert "sink" in rule["help"]["text"]


# --------------------------------------------------------------------------
# Funnel (in format_report)
# --------------------------------------------------------------------------


def _reach_reaching(dep_id, symbols):
    ep = EntrypointReachability(
        id="ep:POST:/import",
        method="POST",
        path="/import",
        handlers=["fn:app.py:do_import"],
        reachable_function_count=1,
        reachable_dependencies=[
            ReachedDependency(
                id=dep_id,
                name="PyYAML",
                version="5.3",
                ecosystem="PyPI",
                symbol=symbols[0] if symbols else None,
                symbols=list(symbols),
                example_path=["ep:POST:/import", dep_id],
            )
        ],
        unresolved_calls_encountered=0,
    )
    repo = RepoReachability(
        reachable_deps=[{"id": dep_id}],
        verdict_by_dep={dep_id: REACHABLE},
    )
    return ReachabilityResult(entrypoints=[ep], repo=repo)


def test_funnel_all_zero_offline():
    # Empty repo, no findings, no network: the funnel renders all-zero.
    correlation = CorrelationResult(findings=[], offline=True, network_ok=False)
    out = report.format_report("repo", KnowledgeGraph(), correlation, ReachabilityResult())
    assert (
        "Funnel: 0 deps · 0 known CVEs · 0 reachable · "
        "0 vulnerable-function confirmed · 0 exploitable "
        "(attacker input reaches the call)" in out
    )


def test_funnel_counts_reachable_confirmed_and_exploitable():
    dep_id = "dep:PyPI:PyYAML"
    graph = _graph_with_deps({dep_id: "requirements.txt"})
    finding = Finding(
        dependency_id=dep_id,
        dependency_name="PyYAML",
        version="5.3",
        ecosystem="PyPI",
        vuln_id="GHSA-pyyaml",
        cve_ids=["CVE-2020-1747"],
        summary="PyYAML code execution via yaml.load",
        fixed_versions=["5.3.1"],
        details="The yaml.load function is the vulnerable sink.",
    )
    correlation = CorrelationResult(findings=[finding], offline=False, network_ok=True)
    reach = _reach_reaching(dep_id, ["yaml.load"])
    taint_map = {
        dep_id: TaintResult(
            verdict="tainted",
            source="request.data",
            sink_symbol="yaml.load",
            entrypoint="POST /import",
            path=["ep:POST:/import", dep_id],
        )
    }

    out = report.format_report("repo", graph, correlation, reach, taint=taint_map)
    # 1 dep, 1 CVE, reachable, symbol-confirmed, and proven exploitable.
    assert (
        "Funnel: 1 deps · 1 known CVEs · 1 reachable · "
        "1 vulnerable-function confirmed · 1 exploitable "
        "(attacker input reaches the call)" in out
    )
    # Additive: the taint map never flips reachable/symbol_match.
    assert finding.reachable is True
    assert finding.symbol_match == "confirmed"
    assert finding.taint == "tainted"


# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------


def _finding_obj(reachable=False, symbol_match="no_path", taint="not_proven"):
    f = Finding(
        dependency_id="d",
        dependency_name="d",
        version="1",
        ecosystem="PyPI",
        vuln_id="GHSA",
        cve_ids=["CVE-2020-0001"],
        summary="",
        fixed_versions=[],
    )
    f.reachable = reachable
    f.symbol_match = symbol_match
    f.taint = taint
    return f


def test_exit_code_never_is_always_zero():
    tainted = _finding_obj(reachable=True, symbol_match="confirmed", taint="tainted")
    assert _compute_exit_code("never", [tainted]) == 0
    assert _compute_exit_code("never", []) == 0


def test_exit_code_reachable():
    assert _compute_exit_code("reachable", [_finding_obj(reachable=True)]) == 1
    assert _compute_exit_code("reachable", [_finding_obj(reachable=False)]) == 0


def test_exit_code_confirmed():
    assert _compute_exit_code("confirmed", [_finding_obj(symbol_match="confirmed")]) == 1
    assert _compute_exit_code("confirmed", [_finding_obj(symbol_match="package_reachable")]) == 0


def test_exit_code_tainted():
    assert _compute_exit_code("tainted", [_finding_obj(taint="tainted")]) == 1
    assert _compute_exit_code("tainted", [_finding_obj(taint="not_proven")]) == 0


def test_exit_code_any():
    assert _compute_exit_code("any", [_finding_obj()]) == 1
    assert _compute_exit_code("any", []) == 0


def test_cli_smoke_offline_fail_on_reachable_is_zero():
    # Offline has no findings, so even --fail-on reachable exits 0.
    assert main(["audit", "samples/golden-app", "--offline", "--fail-on", "reachable"]) == 0


def test_cli_smoke_default_fail_on_never_is_zero():
    assert main(["audit", "samples/golden-app", "--offline"]) == 0


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def test_markdown_contains_funnel_and_table():
    payload, _ = _four_finding_payload()
    md = to_markdown(payload)
    assert "Funnel: 4 deps · 4 known CVEs · 3 reachable" in md
    assert "| Dependency | CVE | Severity | Verdict | Symbol match | Taint | Fixed |" in md
    # The 3 reachable/exploitable findings appear; the unreachable one does not.
    assert "alpha@1.2.3" in md
    assert "beta@4.0.0" in md
    assert "gamma@2.0.0" in md
    assert "delta@0.1.0" not in md


def test_markdown_empty_state_when_nothing_reachable():
    summary = {
        "total_dependencies": 5,
        "total_vulnerabilities": 0,
        "reachable_vulnerabilities": 0,
        "symbol_confirmed_vulnerabilities": 0,
        "taint_confirmed_vulnerabilities": 0,
    }
    md = to_markdown({"summary": summary, "findings": []})
    assert "No reachable vulnerabilities" in md
    assert "Funnel: 5 deps" in md
    assert "| Dependency |" not in md
