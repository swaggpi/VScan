"""End-to-end assertions for the reachability engine against the sample apps.

These exercise :func:`scanner.reachability.compute_reachability` over the real
knowledge graph produced by :func:`scanner.scan.scan_repo` for each sample, so
they pin the demo-centerpiece behaviour: which public entry point reaches which
functions and which dependencies, plus the repo-wide reachable / unreachable
dependency classification and the honesty signals.
"""

from __future__ import annotations

import os

from scanner.graph import KnowledgeGraph
from scanner.reachability import (
    POTENTIALLY_REACHABLE,
    REACHABLE,
    UNREACHABLE,
    EntrypointReachability,
    ReachabilityResult,
    compute_reachability,
)
from scanner.scan import scan_repo

_SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
)


def _reach(sample: str) -> ReachabilityResult:
    return compute_reachability(scan_repo(os.path.join(_SAMPLES, sample)))


def _entrypoint(result: ReachabilityResult, ep_id: str) -> EntrypointReachability:
    for ep in result.entrypoints:
        if ep.id == ep_id:
            return ep
    raise AssertionError(f"entrypoint {ep_id} not found in result")


# -- Python: samples/vulnerable-app -----------------------------------------


def test_python_import_reaches_pyyaml_and_flask():
    result = _reach("vulnerable-app")
    ep = _entrypoint(result, "ep:POST:/import")

    reached = {d.id for d in ep.reachable_dependencies}
    assert "dep:PyPI:PyYAML" in reached
    assert "dep:PyPI:Flask" in reached

    pyyaml = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:PyYAML")
    assert "load" in (pyyaml.symbol or "")


def test_python_health_does_not_reach_pyyaml():
    result = _reach("vulnerable-app")
    ep = _entrypoint(result, "ep:GET:/health")
    reached = {d.id for d in ep.reachable_dependencies}
    assert "dep:PyPI:PyYAML" not in reached


def test_python_pyyaml_example_path():
    result = _reach("vulnerable-app")
    ep = _entrypoint(result, "ep:POST:/import")
    pyyaml = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:PyYAML")
    assert pyyaml.example_path == [
        "ep:POST:/import",
        "fn:app.py:import_data",
        "fn:utils/config_loader.py:load_config",
        "dep:PyPI:PyYAML",
    ]


# -- JavaScript: samples/js-app ---------------------------------------------


def test_js_upload_reaches_lodash_merge():
    result = _reach("js-app")
    ep = _entrypoint(result, "ep:POST:/upload")
    lodash = next(
        (d for d in ep.reachable_dependencies if d.id == "dep:npm:lodash"), None
    )
    assert lodash is not None, "POST /upload should reach lodash"
    assert "merge" in (lodash.symbol or "") or any(
        "merge" in s for s in lodash.symbols
    )


# -- Go: samples/go-app ------------------------------------------------------


def test_go_import_reaches_yaml():
    result = _reach("go-app")
    ep = _entrypoint(result, "ep:POST:/import")
    reached = {d.id for d in ep.reachable_dependencies}
    assert "dep:Go:gopkg.in/yaml.v2" in reached


# -- PHP: samples/php-app (honest empty: no dep call edges by design) --------


def test_php_route_reaches_handler_but_no_dependencies():
    result = _reach("php-app")
    # The sole route reaches its handler function...
    ep = result.entrypoints[0]
    assert ep.handlers, "the PHP route should wire to a handler function"
    assert ep.reachable_function_count >= 1
    # ...and honestly reports no reachable dependencies, because the PHP
    # analyzer emits no dependency call edges.
    assert ep.reachable_dependencies == []


# -- repo-wide classification + honesty --------------------------------------


def test_some_dependency_is_unreachable_from_any_entry_point():
    # In go-app, gin is only called from ``main`` (not reachable from the route),
    # so it is declared but not reachable from any public entry point.
    result = _reach("go-app")
    unreachable_ids = {d["id"] for d in result.repo.unreachable_deps}
    reachable_ids = {d["id"] for d in result.repo.reachable_deps}
    assert "dep:Go:github.com/gin-gonic/gin" in unreachable_ids
    assert "dep:Go:github.com/gin-gonic/gin" not in reachable_ids


def test_unreachable_is_declared_minus_reachable():
    result = _reach("vulnerable-app")
    reachable_ids = {d["id"] for d in result.repo.reachable_deps}
    unreachable_ids = {d["id"] for d in result.repo.unreachable_deps}
    # Flask and PyYAML are reached; the overlap between the two sets is empty.
    assert "dep:PyPI:Flask" in reachable_ids
    assert reachable_ids.isdisjoint(unreachable_ids)
    # A declared-but-never-called PyPI dep lands in unreachable.
    assert "dep:PyPI:urllib3" in unreachable_ids


def test_unresolved_calls_encountered_is_int():
    for sample in ("vulnerable-app", "js-app", "go-app", "php-app"):
        result = _reach(sample)
        for ep in result.entrypoints:
            assert isinstance(ep.unresolved_calls_encountered, int)


def test_result_is_json_serializable():
    import json

    result = _reach("vulnerable-app")
    dumped = json.dumps(result.to_dict())
    assert '"ep:POST:/import"' in dumped
    # The additive three-way verdict layer round-trips through JSON too.
    assert "verdict_by_dep" in dumped
    assert "potentially_reachable" in dumped or "unreachable" in dumped


# -- three-way verdict (soundness) -------------------------------------------
#
# These pin the exact rule: a non-reached dependency is ``unreachable`` ONLY
# when the whole reachable region is fully resolved (zero unresolved calls);
# otherwise it is ``potentially_reachable``. We use the sample apps for the
# real-graph facts and hand-built graphs for the precise unknown/zero-unknown
# boundary.


def test_reached_dependency_verdict_is_reachable():
    # A dep reached by a resolved path -> reachable, in the per-ep record and
    # the repo-wide verdict map.
    result = _reach("vulnerable-app")
    ep = _entrypoint(result, "ep:POST:/import")
    pyyaml = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:PyYAML")
    assert pyyaml.verdict == REACHABLE
    assert result.repo.verdict_by_dep["dep:PyPI:PyYAML"] == REACHABLE
    assert result.repo.verdict_by_dep["dep:PyPI:Flask"] == REACHABLE


def test_fully_resolved_region_yields_unreachable_verdict():
    # vulnerable-app's reachable region (Flask handlers) carries no unresolved
    # calls, so a declared-but-never-called dep is honestly ``unreachable``.
    result = _reach("vulnerable-app")
    assert result.repo.reachable_region_fully_resolved is True
    # urllib3 is declared but reached by no resolved path.
    assert result.repo.verdict_by_dep["dep:PyPI:urllib3"] == UNREACHABLE
    # The binary list is unchanged (strictly additive): urllib3 still appears in
    # unreachable_deps, and its verdict agrees because the region is resolved.
    unreachable_ids = {d["id"] for d in result.repo.unreachable_deps}
    assert "dep:PyPI:urllib3" in unreachable_ids


def test_unresolved_frontier_yields_potentially_reachable_verdict():
    # go-app's reachable region has an unresolved call, so ``gin`` -- declared
    # but reached by no resolved path -- must be ``potentially_reachable``, NOT
    # ``unreachable``, even though the binary list still files it as unreachable.
    result = _reach("go-app")
    assert result.repo.reachable_region_fully_resolved is False
    gin = "dep:Go:github.com/gin-gonic/gin"
    assert result.repo.verdict_by_dep[gin] == POTENTIALLY_REACHABLE
    # Additive: the original binary classification is untouched.
    unreachable_ids = {d["id"] for d in result.repo.unreachable_deps}
    assert gin in unreachable_ids
    # The reached dep is still reachable.
    assert result.repo.verdict_by_dep["dep:Go:gopkg.in/yaml.v2"] == REACHABLE


def _verdict_graph(*, unresolved_on_frontier: bool) -> KnowledgeGraph:
    """A tiny graph: ep -> handler -> helper -> ``reached`` dep, plus a declared
    ``hidden`` dep with no call site. ``helper`` optionally carries an
    unresolved call, which is the only lever that flips the verdict for hidden.
    """
    g = KnowledgeGraph()
    g.add_node("ep:GET:/x", "entrypoint", "GET /x", method="GET", path="/x")
    g.add_node("fn:a.py:handler", "function", "handler")
    g.add_node(
        "fn:a.py:helper",
        "function",
        "helper",
        unresolved_call_count=1 if unresolved_on_frontier else 0,
    )
    g.add_node("dep:PyPI:reached", "dependency", "reached", version="1.0", ecosystem="PyPI")
    g.add_node("dep:PyPI:hidden", "dependency", "hidden", version="2.0", ecosystem="PyPI")
    g.add_edge("ep:GET:/x", "fn:a.py:handler", "route_to_handler")
    g.add_edge("fn:a.py:handler", "fn:a.py:helper", "calls")
    g.add_edge("fn:a.py:helper", "dep:PyPI:reached", "calls", symbol="reached.run")
    return g


def test_handbuilt_zero_unknowns_marks_hidden_unreachable():
    result = compute_reachability(_verdict_graph(unresolved_on_frontier=False))
    assert result.repo.reachable_region_fully_resolved is True
    assert result.repo.verdict_by_dep["dep:PyPI:reached"] == REACHABLE
    assert result.repo.verdict_by_dep["dep:PyPI:hidden"] == UNREACHABLE
    assert result.repo.verdict_counts == {
        REACHABLE: 1,
        POTENTIALLY_REACHABLE: 0,
        UNREACHABLE: 1,
    }
    # Per-entry-point verdict mirrors the repo-wide one here (single entry point).
    ep = _entrypoint(result, "ep:GET:/x")
    assert ep.fully_resolved is True
    assert ep.verdict_by_dep["dep:PyPI:hidden"] == UNREACHABLE
    assert ep.verdict_by_dep["dep:PyPI:reached"] == REACHABLE


def test_handbuilt_one_unknown_marks_hidden_potentially_reachable():
    result = compute_reachability(_verdict_graph(unresolved_on_frontier=True))
    assert result.repo.reachable_region_fully_resolved is False
    # The reached dep is unaffected by the unknown elsewhere on the frontier.
    assert result.repo.verdict_by_dep["dep:PyPI:reached"] == REACHABLE
    # A single unresolved call anywhere on the reachable frontier is enough to
    # forbid an ``unreachable`` verdict for the non-reached dep.
    assert result.repo.verdict_by_dep["dep:PyPI:hidden"] == POTENTIALLY_REACHABLE
    assert result.repo.verdict_counts == {
        REACHABLE: 1,
        POTENTIALLY_REACHABLE: 1,
        UNREACHABLE: 0,
    }
    ep = _entrypoint(result, "ep:GET:/x")
    assert ep.fully_resolved is False
    assert ep.verdict_by_dep["dep:PyPI:hidden"] == POTENTIALLY_REACHABLE
