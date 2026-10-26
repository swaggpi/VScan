"""End-to-end assertions for the reachability engine against the sample apps.

These exercise :func:`scanner.reachability.compute_reachability` over the real
knowledge graph produced by :func:`scanner.scan.scan_repo` for each sample, so
they pin the demo-centerpiece behaviour: which public entry point reaches which
functions and which dependencies, plus the repo-wide reachable / unreachable
dependency classification and the honesty signals.
"""

from __future__ import annotations

import os

from scanner.reachability import (
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
