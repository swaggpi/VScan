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
from scanner.analyzers.javascript_analyzer import (
    JavaScriptAnalyzer,
    _resolve_relative_module,
)
from scanner.analyzers.javascript_analyzer import index_source as js_index
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


# -- B1 (BLOCKER): a function-scoped require must not leak into the module ----


def test_function_scoped_require_does_not_leak_into_module(tmp_path):
    """A lazy ``require`` inside a function must NOT overwrite the module-level
    binding of the same name, so the route stays wired to the safe file and the
    dangerous dependency is not falsely reachable."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "t",
                "version": "1.0.0",
                "dependencies": {"express": "4.18.0", "lodash": "4.17.4"},
            }
        )
    )
    (tmp_path / "safe.js").write_text(
        "function create(req, res) { res.end(); }\n"
        "module.exports = { create };\n"
    )
    (tmp_path / "risky.js").write_text(
        "const _ = require('lodash');\n"
        "function create(req, res) { _.merge({}, req.body); }\n"
        "module.exports = { create };\n"
    )
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "const ctrl = require('./safe');\n"
        "function lazy() { const ctrl = require('./risky'); return ctrl; }\n"
        "app.post('/users', ctrl.create);\n"
        "module.exports = app;\n"
    )
    graph = scan_repo(str(tmp_path))

    ep = graph.get_node("ep:POST:/users")
    assert ep is not None
    assert ep.attrs.get("handler") == "ctrl.create"
    # The route resolves to the MODULE-level ./safe, never the lazy ./risky.
    assert _has_edge(graph, "ep:POST:/users", "fn:safe.js:create", "route_to_handler")
    assert not _has_edge(
        graph, "ep:POST:/users", "fn:risky.js:create", "route_to_handler"
    )

    # The blocker was a verdict flip: lodash was wrongly reachable via /users.
    result = compute_reachability(graph)
    assert result.repo.verdict_by_dep.get("dep:npm:lodash") != REACHABLE
    assert "dep:npm:lodash" not in {d["id"] for d in result.repo.reachable_deps}


# -- S2: a shadowed local/param exported by name is not the top-level fn ------


def test_cjs_export_shadowed_param_not_mapped_to_top_level():
    src = (
        "function handler(req, res) { res.end(); }\n"
        "function register(handler) { exports.handler = handler; }\n"
        "module.exports = { register };\n"
    )
    _rel, exports, _esm = js_index("c.js", src)
    # `exports.handler = handler` binds the PARAMETER, not the top-level
    # `handler` function, so the name must not map to fn:c.js:handler.
    assert exports.get("handler") != "fn:c.js:handler"
    assert "handler" not in exports
    # The genuine module-scope export still resolves.
    assert exports.get("register") == "fn:c.js:register"


# -- S3: a directory specifier resolves to <dir>/index.*, never <dir>.js ------


def test_dir_specifier_prefers_index_over_sibling_file():
    js_files = {"lib.js", "lib/index.js", "lib/sub/x.js"}
    # ``require('..')`` from lib/sub/x.js names the directory lib -> lib/index.js.
    assert _resolve_relative_module("..", "lib/sub/x.js", js_files) == "lib/index.js"
    # Trailing-slash and bare '.' specifiers are directory-only as well.
    assert _resolve_relative_module("../", "lib/sub/x.js", js_files) == "lib/index.js"
    assert _resolve_relative_module("./", "lib/x.js", js_files) == "lib/index.js"
    # A normal (non-directory) specifier still tries the file candidate first.
    assert (
        _resolve_relative_module("./lib", "app.js", {"lib.js", "lib/index.js"})
        == "lib.js"
    )


# -- S4: "exactly one" enforced against reassignment / re-export --------------


def test_cjs_export_non_function_reassignment_drops_name():
    src = (
        "function create(req, res) { res.end(); }\n"
        "function wrap(fn) { return fn; }\n"
        "exports.create = create;\n"
        "exports.create = wrap(create);\n"
    )
    _rel, exports, _esm = js_index("m.js", src)
    # The later non-function assignment poisons the name -> dropped, not stale.
    assert "create" not in exports


def test_cjs_module_exports_reexport_drops_prior_names():
    src = (
        "function create(req, res) { res.end(); }\n"
        "module.exports = { create };\n"
        "module.exports = require('./legacy');\n"
    )
    _rel, exports, _esm = js_index("m.js", src)
    # A wholesale re-export replaces the exports object -> prior names dropped.
    assert "create" not in exports


# -- S5: a pathological source is skipped and recorded, not fatal -------------


def test_nested_array_source_does_not_crash_scan(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0"})
    )
    (tmp_path / "deep.js").write_text("const x = " + "[" * 3000 + "]" * 3000 + ";\n")
    (tmp_path / "ok.js").write_text(
        "function ping() { return 1; }\nmodule.exports = { ping };\n"
    )
    # Must not raise despite the deeply nested (RecursionError-prone) source.
    graph = scan_repo(str(tmp_path))

    deep = graph.get_node("file:deep.js")
    assert deep is not None
    assert deep.attrs.get("parse_error")  # counted by coverage
    assert deep.attrs.get("index_error")
    # The rest of the scan still ran: the healthy file was analyzed.
    assert graph.get_node("fn:ok.js:ping") is not None


# -- N7: an ESM default export is not a CommonJS require() callable -----------


def test_esm_default_not_callable_via_cjs_require(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0"})
    )
    (tmp_path / "esm.js").write_text(
        "export default function handler(req, res) { res.end(); }\n"
    )
    (tmp_path / "app.js").write_text(
        "const e = require('./esm');\n"
        "function run() { return e(); }\n"
        "module.exports = { run };\n"
    )
    graph = scan_repo(str(tmp_path))
    run = graph.get_node("fn:app.js:run")
    assert run is not None
    # `e()` cannot call the ESM default through a CJS require -> unresolved.
    assert "e" in run.attrs.get("unresolved_calls", [])
    assert not any(
        edge.src == "fn:app.js:run"
        and edge.kind == "calls"
        and edge.dst == "fn:esm.js:handler"
        for edge in graph.edges
    )


# -- N8: anonymous enclosing function gets a synthetic, non-colliding prefix ---


def test_anonymous_enclosing_function_no_qualname_collision():
    analyzer = JavaScriptAnalyzer()
    src = (
        "function helper() { return 1; }\n"
        "setTimeout(function () { function helper() { return 2; } helper(); }, 0);\n"
    )
    root = analyzer._get_parser().parse(src.encode("utf-8")).root_node
    quals = [q for q, _n, _b in analyzer._collect_functions(root)]
    # No two functions share a qualname (the nested helper would otherwise merge
    # into the top-level helper node).
    assert len(set(quals)) == len(quals)
    assert "helper" in quals  # the top-level declaration
    nested = [q for q in quals if q != "helper" and q.endswith("helper")]
    assert nested, f"nested helper collided with the top-level one: {quals}"
