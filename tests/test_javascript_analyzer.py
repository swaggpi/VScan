"""End-to-end assertions for the JavaScript analyzer against samples/js-app.

``scanner.analyzers.__init__`` now imports the analyzer (populating the
registry), and importing it here also self-registers it via ``@register``, so
``analyzer_for("javascript")`` resolves either way. The inline-source tests
build a tiny throwaway repo in ``tmp_path`` and scan it, so each false-edge
regression is exercised through the full pipeline (manifest -> analyzer).
"""

from __future__ import annotations

import json
import os

import pytest

# Import triggers @register so analyzer_for("javascript") finds it.
import scanner.analyzers.javascript_analyzer  # noqa: F401
from scanner.scan import scan_repo

JS_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "js-app",
)


def _scan_source(tmp_path, source, deps=None):
    """Write a one-file npm repo to ``tmp_path`` and return its scanned graph.

    ``deps`` declares the package.json dependencies so the matching
    ``dep:npm:*`` nodes exist -- which is what makes the shadowing regressions
    non-vacuous (the import binding is available; only the scope check stops the
    edge).
    """
    if deps is None:
        deps = {"lodash": "4.17.4", "express": "^4.16.0"}
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0", "dependencies": deps})
    )
    (tmp_path / "app.js").write_text(source)
    return scan_repo(str(tmp_path))


def _lodash_call_edges(graph):
    return [e for e in graph.edges if e.kind == "calls" and e.dst == "dep:npm:lodash"]


def _unresolved_everywhere(graph):
    found = set()
    for node in graph.nodes:
        for rep in node.attrs.get("unresolved_calls", []):
            found.add(rep)
    return found


@pytest.fixture(scope="module")
def graph():
    return scan_repo(JS_APP)


# -- dependencies -----------------------------------------------------------


def test_npm_dependencies_present(graph):
    assert graph.get_node("dep:npm:lodash") is not None
    assert graph.get_node("dep:npm:express") is not None


def test_import_edges_module_to_dependency(graph):
    imports = {
        (e.src, e.dst)
        for e in graph.edges
        if e.kind == "imports"
    }
    assert ("mod:server.js", "dep:npm:lodash") in imports
    assert ("mod:server.js", "dep:npm:express") in imports


# -- functions + entry point wiring -----------------------------------------


def test_handle_upload_function_node_exists(graph):
    fn = graph.get_node("fn:server.js:handleUpload")
    assert fn is not None
    assert fn.kind == "function"


def test_post_upload_entrypoint_routes_to_handler(graph):
    ep = graph.get_node("ep:POST:/upload")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/upload"

    route_edges = [
        e
        for e in graph.edges
        if e.kind == "route_to_handler" and e.src == "ep:POST:/upload"
    ]
    assert route_edges, "no route_to_handler edge from POST /upload"
    assert route_edges[0].dst == "fn:server.js:handleUpload"


def test_inline_handler_entrypoint_has_no_fabricated_edge(graph):
    ep = graph.get_node("ep:GET:/ping")
    assert ep is not None
    assert ep.attrs["inline_handler"] is True
    # No route_to_handler edge should point at a fabricated function id.
    route_edges = [
        e
        for e in graph.edges
        if e.kind == "route_to_handler" and e.src == "ep:GET:/ping"
    ]
    assert route_edges == []


# -- resolved call chain reaching lodash -------------------------------------


def test_call_chain_reaches_lodash(graph):
    # handleUpload -> applyDefaults (intra-file call edge).
    assert any(
        e.kind == "calls"
        and e.src == "fn:server.js:handleUpload"
        and e.dst == "fn:server.js:applyDefaults"
        for e in graph.edges
    ), "missing handleUpload -> applyDefaults call edge"

    # applyDefaults -> lodash dependency, with the merge symbol resolved.
    lodash_calls = [
        e
        for e in graph.edges
        if e.kind == "calls"
        and e.src == "fn:server.js:applyDefaults"
        and e.dst == "dep:npm:lodash"
    ]
    assert lodash_calls, "missing applyDefaults -> lodash call edge"
    assert "merge" in lodash_calls[0].attrs.get("symbol", "")


# -- unresolvable call recorded, never edged ---------------------------------


def test_unresolvable_call_recorded_with_no_edge(graph):
    fn = graph.get_node("fn:server.js:handleUpload")
    assert fn is not None
    unresolved = fn.attrs.get("unresolved_calls", [])
    assert "store.persist" in unresolved

    # And absolutely no edge was fabricated for the unknown receiver.
    assert not any(
        e.kind == "calls"
        and e.src == "fn:server.js:handleUpload"
        and "store" in e.dst
        for e in graph.edges
    )


# ===========================================================================
# Regression negatives: false-edge reproductions that had ZERO coverage.
# Each asserts NO fabricated edge, and (for shadowing) that the call was still
# SEEN and recorded as unresolved -- so the test is not vacuous.
# ===========================================================================


# -- B3: closures / callbacks / for-of / catch shadow a module import --------


def test_b3_closure_outer_param_shadows_import(tmp_path):
    # `_` is lodash at module scope, but shadowed by outer's parameter; the
    # nested `inner` closes over that `_`, so `_.merge` must NOT reach lodash.
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "function outer(_) { function inner() { return _.merge({}, {}); } return inner(); }\n",
    )
    assert g.get_node("dep:npm:lodash") is not None  # binding was available
    assert _lodash_call_edges(g) == []
    assert "_.merge" in _unresolved_everywhere(g)


def test_b3_arrow_callback_param_shadows_import(tmp_path):
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "function f(list) { return list.map((_) => _.merge({}, {})); }\n",
    )
    assert g.get_node("dep:npm:lodash") is not None
    assert _lodash_call_edges(g) == []
    assert "_.merge" in _unresolved_everywhere(g)


def test_b3_foreach_callback_param_shadows_import(tmp_path):
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "list.forEach(_ => _.merge({}));\n",
    )
    assert g.get_node("dep:npm:lodash") is not None
    assert _lodash_call_edges(g) == []
    assert "_.merge" in _unresolved_everywhere(g)


def test_b3_for_of_binding_shadows_import(tmp_path):
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "function g(list) { for (const _ of list) { _.merge({}); } }\n",
    )
    assert g.get_node("dep:npm:lodash") is not None
    assert _lodash_call_edges(g) == []
    assert "_.merge" in _unresolved_everywhere(g)


def test_b3_catch_param_shadows_import(tmp_path):
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "function g() { try {} catch (_) { _.merge({}); } }\n",
    )
    assert g.get_node("dep:npm:lodash") is not None
    assert _lodash_call_edges(g) == []
    assert "_.merge" in _unresolved_everywhere(g)


def test_b3_unshadowed_import_still_resolves(tmp_path):
    # Positive control: without shadowing, `_.merge` DOES reach lodash, proving
    # the negatives above are blocked by the scope check, not a broken fixture.
    g = _scan_source(
        tmp_path,
        'const _ = require("lodash");\n'
        "function f(body) { return _.merge({}, body); }\n",
    )
    edges = _lodash_call_edges(g)
    assert edges, "unshadowed _.merge should resolve to lodash"
    assert any("merge" in e.attrs.get("symbol", "") for e in edges)


# -- B4: scope-blind route objects / local_functions ------------------------


def test_b4_non_router_receiver_emits_no_route(tmp_path):
    # `app` is express() in a() (a real router) but new Map() in b() (not a
    # router). Scope-aware resolution keeps /real and drops the false /fake.
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        'function a() { const app = express(); app.get("/real", h1); }\n'
        'function b() { const app = new Map(); app.get("/fake", h2); }\n'
        "function h1(){} function h2(){}\n",
    )
    assert g.get_node("ep:GET:/real") is not None
    assert g.get_node("ep:GET:/fake") is None
    assert not any(e.dst == "fn:app.js:h2" for e in g.edges if e.kind == "route_to_handler")


def test_b4_param_shadowed_handler_no_fn_edge(tmp_path):
    # `register`'s parameter shadows the top-level `handler` function, so the
    # entry point exists but must NOT route to fn:app.js:handler.
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function handler(req, res){}\n"
        'function register(handler){ app.get("/x", handler); }\n',
    )
    ep = g.get_node("ep:GET:/x")
    assert ep is not None
    assert ep.attrs.get("unresolved_handler") == "handler"
    assert [e for e in g.edges if e.kind == "route_to_handler" and e.src == "ep:GET:/x"] == []


def test_b4_out_of_scope_helper_no_call_edge(tmp_path):
    # `helper` is nested in a(); b() cannot reach it. No fabricated call edge,
    # and the two nested helpers get distinct ids (no collision/merge).
    g = _scan_source(
        tmp_path,
        "function a(){ function helper(){} }\n"
        "function c(){ function helper(){} }\n"
        "function b(){ helper(); }\n",
    )
    assert not any(
        e.kind == "calls" and e.src == "fn:app.js:b" and e.dst.endswith(":helper")
        for e in g.edges
    )
    assert g.get_node("fn:app.js:a.helper") is not None
    assert g.get_node("fn:app.js:c.helper") is not None
    assert g.get_node("fn:app.js:helper") is None  # no flat collision id


# -- S10: non-HTTP method labels (all -> ANY, use mount) ---------------------


def test_s10_all_maps_to_any(tmp_path):
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function h(req, res){}\n"
        'app.all("/x", h);\n',
    )
    assert g.get_node("ep:ALL:/x") is None
    ep = g.get_node("ep:ANY:/x")
    assert ep is not None and ep.attrs["method"] == "ANY"
    assert ep.attrs.get("mount") is None  # all is not a mount


def test_s10_use_with_path_is_any_mount(tmp_path):
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function mw(req, res, next){}\n"
        'app.use("/api", mw);\n',
    )
    assert g.get_node("ep:USE:/api") is None
    ep = g.get_node("ep:ANY:/api")
    assert ep is not None
    assert ep.attrs["mount"] is True


def test_s10_use_without_path_is_not_entrypoint(tmp_path):
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function mw(req, res, next){}\n"
        "app.use(mw);\n",
    )
    assert [n for n in g.nodes if n.kind == "entrypoint"] == []


# -- S11: multi-fragment string paths are not truncated ----------------------


def test_s11_multi_fragment_path_not_truncated(tmp_path):
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function h(req, res){}\n"
        'app.get("/a\\nb", h);\n',
    )
    # Must not collapse to just "/a" at the first fragment boundary.
    assert g.get_node("ep:GET:/a") is None
    eps = [n for n in g.nodes if n.kind == "entrypoint" and n.attrs.get("method") == "GET"]
    assert len(eps) == 1
    path = eps[0].attrs["path"]
    assert path != "/a"
    assert path.startswith("/a") and path.endswith("b")


# -- convention: handler_collisions on a duplicate ep id ---------------------


def test_duplicate_route_records_handler_collision(tmp_path):
    g = _scan_source(
        tmp_path,
        'const express = require("express");\n'
        "const app = express();\n"
        "function h1(req, res){} function h2(req, res){}\n"
        'app.get("/dup", h1);\n'
        'app.get("/dup", h2);\n',
    )
    ep = g.get_node("ep:GET:/dup")
    assert ep is not None
    collisions = ep.attrs.get("handler_collisions", [])
    assert {"handler": "h2", "handler_file": "app.js"} in collisions
    dsts = {e.dst for e in g.edges if e.kind == "route_to_handler" and e.src == "ep:GET:/dup"}
    assert "fn:app.js:h1" in dsts
    assert "fn:app.js:h2" in dsts


# -- convention: Koa via new-expression is a recognised router ---------------


def test_koa_new_expression_is_a_router(tmp_path):
    g = _scan_source(
        tmp_path,
        'const Koa = require("koa");\n'
        "const app = new Koa();\n"
        "function h(ctx){}\n"
        'app.use("/k", h);\n',
        deps={"koa": "2.0.0"},
    )
    ep = g.get_node("ep:ANY:/k")
    assert ep is not None
    assert ep.attrs["framework"] == "koa"
    assert ep.attrs["mount"] is True
