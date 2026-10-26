"""End-to-end assertions for the Go analyzer against samples/go-app plus
focused negative tests over inline fixtures built under ``tmp_path``.

The package ``__init__`` now imports ``scanner.analyzers.go_analyzer`` (running
its ``@register`` decorator), so ``scan_repo`` dispatches ``.go`` files to it;
the explicit import below is kept as a belt-and-braces guard should that change.
"""

from __future__ import annotations

import os

import pytest

import scanner.analyzers.go_analyzer  # noqa: F401  (registers the analyzer)
from scanner.scan import scan_repo

GO_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "go-app",
)

GIN = "dep:Go:github.com/gin-gonic/gin"
YAML = "dep:Go:gopkg.in/yaml.v2"
MOD = "mod:main.go"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(GO_APP)


def _edges(graph, kind):
    return [e for e in graph.edges if e.kind == kind]


def test_go_dependencies_present(graph):
    dep_ids = {n.id for n in graph.nodes_of_kind("dependency")}
    assert GIN in dep_ids
    assert YAML in dep_ids


def test_functions_declared(graph):
    fn_ids = {n.id for n in graph.nodes_of_kind("function")}
    assert "fn:main.go:importHandler" in fn_ids
    assert "fn:main.go:loadConfig" in fn_ids
    assert "fn:main.go:main" in fn_ids
    # declares edge module -> function.
    declares = {(e.src, e.dst) for e in _edges(graph, "declares")}
    assert (MOD, "fn:main.go:importHandler") in declares


def test_import_maps_to_dep_longest_prefix(graph):
    imports = {(e.src, e.dst) for e in _edges(graph, "imports")}
    # gin import path == dep module exactly; yaml likewise.
    assert (MOD, GIN) in imports
    assert (MOD, YAML) in imports
    # net/http is stdlib -> recorded on the module, no dep edge.
    mod_node = graph.get_node(MOD)
    assert "net/http" in mod_node.attrs.get("stdlib_imports", [])
    # Exact import-edge set: ONLY the two dependency imports exist. Nothing is
    # fabricated for the stdlib net/http import (stronger than a substring probe).
    assert imports == {(MOD, GIN), (MOD, YAML)}


def test_route_to_handler_edge(graph):
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"
    routed = {(e.src, e.dst) for e in _edges(graph, "route_to_handler")}
    assert ("ep:POST:/import", "fn:main.go:importHandler") in routed


def test_call_into_dependency_has_symbol(graph):
    yaml_calls = [
        e
        for e in _edges(graph, "calls")
        if e.dst == YAML and e.src == "fn:main.go:loadConfig"
    ]
    assert len(yaml_calls) == 1
    assert yaml_calls[0].attrs.get("symbol") == "yaml.Unmarshal"


def test_intra_file_call_edge(graph):
    calls = {(e.src, e.dst) for e in _edges(graph, "calls")}
    assert ("fn:main.go:importHandler", "fn:main.go:loadConfig") in calls


def test_unresolvable_call_recorded_with_no_edge(graph):
    handler = graph.get_node("fn:main.go:importHandler")
    unresolved = handler.attrs.get("unresolved_calls", [])
    assert "c.somethingUnknown" in unresolved
    # The only call edge out of importHandler is the resolved intra-file one;
    # the unresolvable method call produced no edge.
    out = {e.dst for e in _edges(graph, "calls") if e.src == "fn:main.go:importHandler"}
    assert out == {"fn:main.go:loadConfig"}


# ---------------------------------------------------------------------------
# Negative / regression tests over inline fixtures (reproduce the review's
# false-edge snippets; each must produce NO fabricated edge).
# ---------------------------------------------------------------------------


def _scan_go(tmp_path, main_go, requires=()):
    """Write a tiny Go repo (go.mod + main.go) under tmp_path and scan it."""
    req_block = ""
    if requires:
        lines = "\n".join(f"\t{mod} {ver}" for mod, ver in requires)
        req_block = f"\nrequire (\n{lines}\n)\n"
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.19\n" + req_block
    )
    (tmp_path / "main.go").write_text(main_go)
    return scan_repo(str(tmp_path))


def _unresolved(graph, fn_id):
    node = graph.get_node(fn_id)
    assert node is not None, fn_id
    return node.attrs.get("unresolved_calls", [])


# -- B1: verb calls on non-router receivers are NOT routes ------------------

B1_SRC = """package main

import "github.com/go-resty/resty/v2"

func handler() {}

func main() {
	client := resty.New()
	client.Get("/users/1")       // HTTP client call -- NOT a route
	kv.Put("/config/x", handler) // KV store -- NOT a route
	cache.Delete("/k")           // cache -- NOT a route
}
"""


def test_b1_non_router_verb_calls_are_not_routes(tmp_path):
    graph = _scan_go(
        tmp_path, B1_SRC, requires=[("github.com/go-resty/resty/v2", "v2.7.0")]
    )
    # No entrypoints are fabricated and no route_to_handler edges exist.
    assert graph.nodes_of_kind("entrypoint") == []
    assert _edges(graph, "route_to_handler") == []
    ep_ids = {n.id for n in graph.nodes_of_kind("entrypoint")}
    assert "ep:GET:/users/1" not in ep_ids
    assert "ep:PUT:/config/x" not in ep_ids
    assert "ep:DELETE:/k" not in ep_ids
    # The receiver-less method calls are recorded as unresolved, not guessed.
    unresolved = _unresolved(graph, "fn:main.go:main")
    assert "client.Get" in unresolved
    assert "kv.Put" in unresolved
    assert "cache.Delete" in unresolved


# -- B2: a shadowing local binding suppresses resolution through an import --

B2_SRC = """package main

import "gopkg.in/yaml.v2"

func f(a, yaml int)    { yaml.Unmarshal(nil, nil) }
func g(yaml ...string) { yaml.Unmarshal(nil, nil) }
func h() (yaml int)    { yaml.Unmarshal(nil, nil); return 0 }
func k()               { fn := func(yaml int) { yaml.Unmarshal(nil, nil) }; fn(1) }
"""


def test_b2_shadowing_bindings_suppress_dep_edge(tmp_path):
    graph = _scan_go(tmp_path, B2_SRC, requires=[("gopkg.in/yaml.v2", "v2.2.2")])
    # NOT a single calls edge reaches the yaml dependency.
    yaml_edges = [e for e in _edges(graph, "calls") if e.dst == YAML]
    assert yaml_edges == []
    # Each shadowing form records the call as unresolved instead.
    for fn in ("f", "g", "h", "k"):
        assert "yaml.Unmarshal" in _unresolved(graph, f"fn:main.go:{fn}"), fn


# -- B6: a locally-bound handler is not resolved to the same-named func -----

B6_SRC = """package main

import "github.com/gin-gonic/gin"

func handler() {}

func wrap(x int) gin.HandlerFunc { return nil }

func main() {
	handler := wrap(1) // local var shadows the package-level func
	r := gin.Default()
	r.GET("/x", handler)
}
"""


def test_b6_locally_bound_handler_no_fn_edge(tmp_path):
    graph = _scan_go(
        tmp_path, B6_SRC, requires=[("github.com/gin-gonic/gin", "v1.6.0")]
    )
    # The entrypoint is still emitted (r is a real gin router) ...
    ep = graph.get_node("ep:GET:/x")
    assert ep is not None
    assert ep.attrs["method"] == "GET"
    # ... but the handler name is locally bound, so NO fn edge is fabricated.
    assert ep.attrs.get("handler") is None
    assert ep.attrs.get("unresolved_handler") == "handler"
    routed = {(e.src, e.dst) for e in _edges(graph, "route_to_handler")}
    assert ("ep:GET:/x", "fn:main.go:handler") not in routed
    assert routed == set()


# -- S9: method qualname uses the Class.method convention -------------------

S9_SRC = """package main

type Server struct{}

func (s *Server) Handle() {}
func (s Server) Name() string { return "" }
"""


def test_s9_method_qualname_convention(tmp_path):
    graph = _scan_go(tmp_path, S9_SRC)
    fn_ids = {n.id for n in graph.nodes_of_kind("function")}
    assert "fn:main.go:Server.Handle" in fn_ids
    assert "fn:main.go:Server.Name" in fn_ids
    assert "fn:main.go:(Server).Handle" not in fn_ids
    handle = graph.get_node("fn:main.go:Server.Handle")
    name = graph.get_node("fn:main.go:Server.Name")
    assert handle.attrs.get("pointer_receiver") is True
    assert not name.attrs.get("pointer_receiver")


# -- S11: a multi-fragment string path is not truncated at the first escape -

S11_SRC = r"""package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/a\nb", nil)
}
"""


def test_s11_multifragment_string_path(tmp_path):
    graph = _scan_go(
        tmp_path, S11_SRC, requires=[("github.com/gin-gonic/gin", "v1.6.0")]
    )
    # The path keeps all fragments (``/a`` + ``\n`` + ``b``), not just ``/a``.
    ep = graph.get_node("ep:GET:/a\\nb")
    assert ep is not None
    assert ep.attrs["path"] == "/a\\nb"
    assert graph.get_node("ep:GET:/a") is None
