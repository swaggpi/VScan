"""Sound cross-file JavaScript resolution, against samples/js-multifile-app.

The sample is a small multi-file Express app:

    server.js          const ctrl = require('./controllers/user')
                       const { sanitize } = require('./util')
                       app.post('/users', ctrl.create)        (cross-file handler)
    controllers/user.js  exports `create`; calls `sanitize` (util) and `_.merge`
    util.js            exports `sanitize`; calls lodash

So the chain  POST /users -> create -> {sanitize, lodash}  is fully cross-file.

These tests assert the POSITIVE cross-file edges, that the old lodash is
reachable through that chain, and the NEGATIVES required by the cardinal rule:
a specifier that does not resolve to a repo file, a dynamic/computed require,
and a bare package require each fabricate no cross-file edge (the first two are
still recorded as unresolved, so the assertions are not vacuous).
"""

from __future__ import annotations

import json
import os

import pytest

# Import triggers @register so analyzer_for("javascript") resolves.
import scanner.analyzers.javascript_analyzer  # noqa: F401
from scanner.reachability import REACHABLE, compute_reachability
from scanner.scan import scan_repo

MULTI_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "js-multifile-app",
)


@pytest.fixture(scope="module")
def graph():
    return scan_repo(MULTI_APP)


def _has_edge(graph, src, dst, kind):
    return any(e.src == src and e.dst == dst and e.kind == kind for e in graph.edges)


# -- positive: cross-file route handler --------------------------------------


def test_cross_file_route_to_handler(graph):
    ep = graph.get_node("ep:POST:/users")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    # The handler reference `ctrl.create` resolved to the cross-file function.
    assert ep.attrs.get("handler") == "ctrl.create"
    assert _has_edge(
        graph, "ep:POST:/users", "fn:controllers/user.js:create", "route_to_handler"
    )


# -- positive: cross-file call edge ------------------------------------------


def test_cross_file_call_edge_create_to_sanitize(graph):
    # `create` destructures `sanitize` from ../util and calls it: a cross-file
    # `calls` edge into the single exported function.
    assert _has_edge(
        graph, "fn:controllers/user.js:create", "fn:util.js:sanitize", "calls"
    )


# -- positive: old lodash reachable through the cross-file chain -------------


def test_lodash_reachable_through_cross_file_chain(graph):
    # create -> lodash directly (via _.merge), with lodash imported in the
    # controller module.
    assert any(
        e.src == "fn:controllers/user.js:create"
        and e.dst == "dep:npm:lodash"
        and e.kind == "calls"
        for e in graph.edges
    )
    result = compute_reachability(graph)
    # The POST /users entry point reaches lodash only through the resolved
    # cross-file route_to_handler + calls edges.
    assert result.repo.verdict_by_dep.get("dep:npm:lodash") == REACHABLE
    assert "dep:npm:lodash" in {d["id"] for d in result.repo.reachable_deps}


# -- negatives: cardinal rule -- no fabricated cross-file edges ---------------


def test_unresolvable_relative_module_no_edge_but_recorded(graph):
    # `require('./does-not-exist')` resolves to no repo file, so `missing.run()`
    # must be RECORDED as unresolved and produce no edge/node.
    boot = graph.get_node("fn:server.js:bootstrap")
    assert boot is not None
    assert "missing.run" in boot.attrs.get("unresolved_calls", [])
    assert not any("does-not-exist" in n.id for n in graph.nodes)
    # No calls edge out of bootstrap points at a fabricated controller/util fn
    # for the missing module.
    assert not any(
        e.src == "fn:server.js:bootstrap"
        and e.kind == "calls"
        and e.dst.startswith("fn:")
        and e.dst != "fn:util.js:sanitize"
        for e in graph.edges
    )


def test_dynamic_require_no_edge_but_recorded(graph):
    # `require(modName)` is dynamic/computed: `dynamic.go()` stays unresolved.
    boot = graph.get_node("fn:server.js:bootstrap")
    assert boot is not None
    assert "dynamic.go" in boot.attrs.get("unresolved_calls", [])


def test_bare_require_is_dependency_not_cross_file(graph):
    # A bare `require('lodash')` yields a dependency import edge, and the bare
    # call `_.cloneDeep` is a dependency call, never a cross-file fn edge.
    assert _has_edge(graph, "mod:server.js", "dep:npm:lodash", "imports")
    cloneDeep = [
        e
        for e in graph.edges
        if e.kind == "calls"
        and e.src == "fn:server.js:bootstrap"
        and e.dst == "dep:npm:lodash"
    ]
    assert cloneDeep, "bare lodash call not recorded as a dependency call"
    assert any("cloneDeep" in str(e.attrs.get("symbol", "")) for e in cloneDeep)


# -- negative: a relative specifier to a non-existent file in isolation ------


def test_isolated_unresolved_relative_specifier(tmp_path):
    """A one-file repo whose only relative import misses: no cross-file edge."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"lodash": "4.17.4"}})
    )
    (tmp_path / "app.js").write_text(
        "const gone = require('./nope');\n"
        "function run() { return gone.handle(); }\n"
        "module.exports = { run };\n"
    )
    graph = scan_repo(str(tmp_path))
    run = graph.get_node("fn:app.js:run")
    assert run is not None
    assert "gone.handle" in run.attrs.get("unresolved_calls", [])
    # No route/call edge was fabricated to any fn: target.
    assert not any(
        e.src == "fn:app.js:run" and e.kind == "calls" and e.dst.startswith("fn:")
        for e in graph.edges
    )
