"""End-to-end assertions for the coverage / confidence report.

These exercise :func:`scanner.coverage.compute_coverage` over the real
knowledge graph produced by :func:`scanner.scan.scan_repo`, pinning the
quantitative summary that makes the "reachability is a lower bound" honesty
concrete: how many files parsed, what fraction of call sites resolved, the
dependency verdict breakdown, and the confidence note (including the
zero-entry-point case). No network access is involved.
"""

from __future__ import annotations

import os

from scanner.coverage import CoverageReport, compute_coverage
from scanner.graph import KnowledgeGraph
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo

_SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)


def _coverage() -> CoverageReport:
    graph = scan_repo(_SAMPLE_APP)
    reach = compute_reachability(graph)
    return compute_coverage(graph, reach)


# -- counts match the known sample ------------------------------------------


def test_file_counts_and_parse_rate_match_sample():
    cov = _coverage()
    assert cov.files.total == 11
    assert cov.files.by_language.get("python") == 3
    # The clean sample parses fully.
    assert cov.files.parse_errors == 0
    assert cov.files.parsed == 11
    assert cov.files.parse_success_rate == 1.0
    # by_language counts cover every file.
    assert sum(cov.files.by_language.values()) == cov.files.total


def test_function_counts_match_sample():
    cov = _coverage()
    assert cov.functions.total == 3
    # Functions inherit language from their declaring file (via relpath).
    assert cov.functions.by_language == {"python": 3}


def test_entrypoint_counts_match_sample():
    cov = _coverage()
    assert cov.entrypoints.total == 2
    assert cov.entrypoints.by_framework == {"flask": 2}
    assert cov.entrypoints.unresolved_routes == 0
    assert cov.entrypoints.without_handler == 0


def test_call_site_resolution_rate_is_a_sensible_fraction():
    cov = _coverage()
    resolved = cov.call_sites.resolved
    unresolved = cov.call_sites.unresolved
    assert resolved > 0
    assert 0.0 <= cov.call_sites.resolution_rate <= 1.0
    assert cov.call_sites.resolution_rate == resolved / (resolved + unresolved)


def test_dependency_verdict_breakdown_matches_reachability():
    graph = scan_repo(_SAMPLE_APP)
    reach = compute_reachability(graph)
    cov = compute_coverage(graph, reach)

    total_deps = len(graph.nodes_of_kind("dependency"))
    assert cov.dependencies.total == total_deps
    assert (
        cov.dependencies.with_call_site + cov.dependencies.without_call_site
        == total_deps
    )
    # The verdict breakdown mirrors the reachability engine exactly.
    assert cov.dependencies.verdict_breakdown == {
        "reachable": reach.repo.verdict_counts.get("reachable", 0),
        "potentially_reachable": reach.repo.verdict_counts.get(
            "potentially_reachable", 0
        ),
        "unreachable": reach.repo.verdict_counts.get("unreachable", 0),
    }
    # Breakdown totals sum to all declared dependencies.
    assert sum(cov.dependencies.verdict_breakdown.values()) == total_deps


def test_verdict_breakdown_absent_without_reachability():
    graph = scan_repo(_SAMPLE_APP)
    cov = compute_coverage(graph)
    assert cov.dependencies.verdict_breakdown is None


def test_to_dict_is_json_serializable():
    import json

    cov = _coverage()
    payload = json.dumps(cov.to_dict())
    restored = json.loads(payload)
    assert restored["files"]["total"] == 11
    assert "confidence_note" in restored


# -- confidence note honesty -------------------------------------------------


def test_confidence_note_states_lower_bound_and_names_unresolved_calls():
    cov = _coverage()
    note = cov.confidence_note.lower()
    assert "lower bound" in note
    # The sample has exactly one unresolved call site; the note must name it.
    assert cov.call_sites.unresolved == 1
    assert "unresolved call site" in note


def test_zero_entrypoint_confidence_note_fires():
    # A graph with files and dependencies but no entry points: reachability
    # coverage is effectively nil, and the note must say so.
    graph = KnowledgeGraph()
    graph.add_node("file:lib.py", "file", "lib.py", language="python", relpath="lib.py")
    graph.add_node("dep:pypi:requests", "dependency", "requests", ecosystem="pypi")
    cov = compute_coverage(graph, compute_reachability(graph))
    assert cov.entrypoints.total == 0
    assert "effectively nil" in cov.confidence_note.lower()
    assert "nothing" in cov.confidence_note.lower()


# -- parse failures are reported ---------------------------------------------


def test_parse_error_file_shows_in_report(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    # A syntactically broken Python module and one that parses cleanly.
    (repo / "broken.py").write_text("def oops(:\n    return 1\n")
    (repo / "ok.py").write_text("def fine():\n    return 1\n")
    (repo / "requirements.txt").write_text("flask==2.0.0\n")

    graph = scan_repo(str(repo))
    cov = compute_coverage(graph)

    assert cov.files.parse_errors >= 1
    assert cov.files.parsed < cov.files.total
    assert 0.0 <= cov.files.parse_success_rate < 1.0
    assert "failed to parse" in cov.confidence_note.lower()
