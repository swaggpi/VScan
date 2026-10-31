"""Starlette (ASGI) route-LIST detection + taint sources.

Starlette declares routes as a LIST of ``Route``/``Mount`` objects bound on the
``Starlette(routes=...)`` application (no decorators). These tests scan the
``samples/starlette-app`` fixture once and assert the analyzer finds those
routes, composes ``Mount`` prefixes, resolves endpoints, and flows awaited
request sources (``await request.json()``) into a dependency sink -- while never
fabricating a route for a dynamic path or an unresolved endpoint.
"""

from __future__ import annotations

import os
import textwrap

import pytest

from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.taint import TAINTED, compute_taint

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "starlette-app",
)


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


def _routed_to(graph, ep_id):
    return {
        e.dst
        for e in graph.edges
        if e.kind == "route_to_handler" and e.src == ep_id
    }


def _scan_tmp(tmp_path, files: dict[str, str]):
    for name, src in files.items():
        (tmp_path / name).write_text(textwrap.dedent(src).lstrip())
    return scan_repo(str(tmp_path))


def _unresolved_routes(graph) -> list[str]:
    notes: list[str] = []
    for mod in graph.nodes_of_kind("module"):
        notes.extend(mod.attrs.get("unresolved_routes", []))
    return notes


# -- Route-list detection -----------------------------------------------------


def test_route_list_emits_post_route_with_methods_kwarg(graph):
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None, "Route(..., methods=['POST']) not detected"
    assert ep.attrs.get("framework") == "starlette"
    assert ep.attrs.get("handler") == "import_endpoint"
    assert ep.attrs.get("handler_file") == "app.py"
    assert "fn:app.py:import_endpoint" in _routed_to(graph, "ep:POST:/import")
    # A POST route must NOT also appear as the default GET.
    assert graph.get_node("ep:GET:/import") is None


def test_route_without_methods_defaults_to_get(graph):
    ep = graph.get_node("ep:GET:/user/{id}")
    assert ep is not None, "Route with no methods= should default to GET"
    assert ep.attrs.get("framework") == "starlette"
    assert "fn:app.py:user_endpoint" in _routed_to(graph, "ep:GET:/user/{id}")


def test_mount_prefix_composes_onto_nested_route(graph):
    ep = graph.get_node("ep:GET:/api/items")
    assert ep is not None, "Mount('/api', routes=[...]) prefix was not composed"
    assert ep.attrs.get("framework") == "starlette"
    assert "fn:app.py:items_endpoint" in _routed_to(graph, "ep:GET:/api/items")
    # The un-prefixed local path must NOT also exist.
    assert graph.get_node("ep:GET:/items") is None


def test_no_spurious_routes(graph):
    starlette_eps = {
        n.id
        for n in graph.nodes_of_kind("entrypoint")
        if n.attrs.get("framework") == "starlette"
    }
    assert starlette_eps == {
        "ep:POST:/import",
        "ep:GET:/user/{id}",
        "ep:GET:/api/items",
    }
    assert _unresolved_routes(graph) == []


# -- Taint: awaited request source flows into a dependency sink ---------------


def test_pyyaml_is_reachable_and_tainted(graph):
    reach = compute_reachability(graph)
    taint = compute_taint(graph, reach, os.path.abspath(SAMPLE_APP))
    result = taint["dep:PyPI:PyYAML"]
    assert result.verdict == TAINTED
    assert result.source == "request.json"  # await request.json()
    assert result.sink_symbol == "yaml.load"
    assert result.entrypoint == "POST /import"
    assert result.path == [
        "ep:POST:/import",
        "fn:app.py:import_endpoint",
        "fn:config.py:load_config",
        "dep:PyPI:PyYAML",
    ]


# -- Other Starlette registration forms (throwaway repos) ---------------------


def test_inline_add_route_and_decorator_forms(tmp_path):
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from starlette.applications import Starlette
                from starlette.routing import Route

                async def a(request): ...
                async def b(request): ...

                app = Starlette(routes=[Route("/a", a, methods=["PUT"])])
                app.add_route("/b", b, methods=["DELETE"])

                @app.route("/c", methods=["POST"])
                async def c2(request): ...
            """,
        },
    )
    assert graph.get_node("ep:PUT:/a") is not None  # inline Starlette(routes=[...])
    assert graph.get_node("ep:DELETE:/b") is not None  # imperative add_route
    assert graph.get_node("ep:POST:/c") is not None  # @app.route decorator
    for ep_id, fn in (
        ("ep:PUT:/a", "fn:app.py:a"),
        ("ep:DELETE:/b", "fn:app.py:b"),
        ("ep:POST:/c", "fn:app.py:c2"),
    ):
        assert fn in _routed_to(graph, ep_id)


def test_mount_subapp_composes_without_bare_route(tmp_path):
    # Mount(app=Starlette(routes=[...])) best-effort: compose the prefix and do
    # NOT also emit the sub-application's routes standalone at no prefix.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from starlette.applications import Starlette
                from starlette.routing import Route, Mount

                async def items(request): ...

                sub = Starlette(routes=[Route("/items", items)])
                app = Starlette(routes=[Mount("/api", app=sub)])
            """,
        },
    )
    assert graph.get_node("ep:GET:/api/items") is not None
    assert graph.get_node("ep:GET:/items") is None


# -- Cardinal rule: negatives -------------------------------------------------


def test_non_literal_path_and_unresolved_endpoint(tmp_path):
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                import os
                from starlette.applications import Starlette
                from starlette.routing import Route

                async def known(request): ...
                DYN = os.environ.get("P", "/x")

                app = Starlette(routes=[
                    Route(DYN, known),              # non-literal path: no route
                    Route("/ok", some_unknown_ep),  # unresolved endpoint
                ])
            """,
        },
    )
    # Non-literal path must not fabricate any route, and the dynamic value is
    # recorded rather than silently dropped.
    assert graph.get_node("ep:GET:/x") is None
    for e in graph.edges:
        if e.kind == "route_to_handler":
            assert e.dst != "fn:app.py:known"
    notes = _unresolved_routes(graph)
    assert any("non-literal path" in n for n in notes), notes

    # The literal-path route with an unresolved endpoint still emits (the route
    # is real) but carries no handler edge -- never a wrong edge, never a crash.
    ep = graph.get_node("ep:GET:/ok")
    assert ep is not None
    assert ep.attrs.get("handler") is None
    assert ep.attrs.get("unresolved_handler") == "some_unknown_ep"
    assert _routed_to(graph, "ep:GET:/ok") == set()
