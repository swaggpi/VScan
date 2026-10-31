"""Tests for broadened Go web-framework coverage: gorilla/mux and gofiber/fiber.

Everything here is OFFLINE and deterministic (no network, no ``go mod
download``): routes come from the single-file analyzer and taint is a pure
static pass over re-parsed source on proven reachability paths.

Coverage:
* mux  -- ``r.HandleFunc(path, h).Methods("POST")`` emits ``ep:POST:/path``
  (framework ``mux``); a chained multi-verb ``.Methods("GET","POST")`` emits one
  entrypoint per verb; a bare ``HandleFunc`` with no ``.Methods`` defaults to
  ``ANY``; the handler resolves and the ``r.FormValue -> yaml.Unmarshal`` flow
  is proven ``tainted`` on the real ``samples/go-mux-app`` fixture.
* fiber -- ``app.Post(path, h)`` emits ``ep:POST:/path`` (framework ``fiber``),
  the ``/v2`` module suffix is tolerated, the handler resolves, and both
  ``c.FormValue`` and ``c.BodyParser(&x)`` prove the ``yaml.Unmarshal`` flow.
* NEGATIVE -- a ``.HandleFunc`` on a receiver that is neither a mux router nor
  net/http is NOT a route (no spurious entrypoint).
"""

from __future__ import annotations

import os

from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.taint import NOT_PROVEN, TAINTED, compute_taint

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_MUX_APP = os.path.join(REPO, "samples", "go-mux-app")
GO_FIBER_APP = os.path.join(REPO, "samples", "go-fiber-app")

_YAML = "dep:Go:gopkg.in/yaml.v2"

_GO_MOD = """\
module example.com/app

go 1.19

require (
	github.com/gofiber/fiber/v2 v2.52.0
	github.com/gorilla/mux v1.8.0
	gopkg.in/yaml.v2 v2.2.2
)
"""


def _scan(tmp_path, main_go: str):
    (tmp_path / "go.mod").write_text(_GO_MOD)
    (tmp_path / "main.go").write_text(main_go)
    return scan_repo(str(tmp_path))


def _entrypoints(graph) -> dict[str, str]:
    """Map each entrypoint id -> its framework label."""
    return {n.id: n.attrs.get("framework") for n in graph.nodes_of_kind("entrypoint")}


def _yaml_verdict(graph, path: str) -> str:
    reach = compute_reachability(graph)
    return compute_taint(graph, reach, os.path.abspath(path))[_YAML].verdict


# -- mux: real-fixture end-to-end ---------------------------------------------


def test_mux_app_route_and_taint():
    graph = scan_repo(GO_MUX_APP)
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"
    assert ep.attrs["framework"] == "mux"
    assert ep.attrs["handler"] == "importHandler"
    assert ep.attrs["handler_file"] == "main.go"
    # The chained .Methods("POST") pins the verb -- no ANY entrypoint.
    assert graph.get_node("ep:ANY:/import") is None
    routed = {(e.src, e.dst) for e in graph.edges if e.kind == "route_to_handler"}
    assert ("ep:POST:/import", "fn:main.go:importHandler") in routed

    reach = compute_reachability(graph)
    result = compute_taint(graph, reach, GO_MUX_APP)[_YAML]
    assert result.verdict == TAINTED
    assert result.source == "r.FormValue"
    assert result.sink_symbol == "yaml.Unmarshal"
    assert result.entrypoint == "POST /import"
    assert result.path == [
        "ep:POST:/import",
        "fn:main.go:importHandler",
        "fn:main.go:parseYAML",
        "dep:Go:gopkg.in/yaml.v2",
    ]


# -- mux: .Methods parsing variants -------------------------------------------


def test_mux_handlefunc_without_methods_defaults_to_any(tmp_path):
    graph = _scan(
        tmp_path,
        """\
package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func h(w http.ResponseWriter, r *http.Request) {}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/p", h)
}
""",
    )
    assert _entrypoints(graph) == {"ep:ANY:/p": "mux"}


def test_mux_methods_multi_verb_emits_one_entrypoint_each(tmp_path):
    graph = _scan(
        tmp_path,
        """\
package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func h(w http.ResponseWriter, r *http.Request) {}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/p", h).Methods("GET", "post")
}
""",
    )
    # Both verbs, uppercased, each its own entrypoint; handler resolves on both.
    assert _entrypoints(graph) == {"ep:GET:/p": "mux", "ep:POST:/p": "mux"}
    routed = {(e.src, e.dst) for e in graph.edges if e.kind == "route_to_handler"}
    assert ("ep:GET:/p", "fn:main.go:h") in routed
    assert ("ep:POST:/p", "fn:main.go:h") in routed


# -- NEGATIVE: .HandleFunc on a non-router receiver is NOT a route ------------


def test_handlefunc_on_non_router_is_not_a_route(tmp_path):
    graph = _scan(
        tmp_path,
        """\
package main

func h() {}

func main() {
	thing := builder.New()
	thing.HandleFunc("/p", h) // not a mux/net-http router -- NOT a route
}
""",
    )
    assert graph.nodes_of_kind("entrypoint") == []
    assert [e for e in graph.edges if e.kind == "route_to_handler"] == []


# -- fiber: real-fixture end-to-end -------------------------------------------


def test_fiber_app_route_and_taint():
    graph = scan_repo(GO_FIBER_APP)
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"
    assert ep.attrs["framework"] == "fiber"
    assert ep.attrs["handler"] == "importHandler"
    assert ep.attrs["handler_file"] == "main.go"
    routed = {(e.src, e.dst) for e in graph.edges if e.kind == "route_to_handler"}
    assert ("ep:POST:/import", "fn:main.go:importHandler") in routed

    reach = compute_reachability(graph)
    result = compute_taint(graph, reach, GO_FIBER_APP)[_YAML]
    assert result.verdict == TAINTED
    assert result.source == "c.FormValue"
    assert result.sink_symbol == "yaml.Unmarshal"
    assert result.entrypoint == "POST /import"
    assert result.path == [
        "ep:POST:/import",
        "fn:main.go:importHandler",
        "fn:main.go:parseYAML",
        "dep:Go:gopkg.in/yaml.v2",
    ]


# -- fiber: source families ---------------------------------------------------


def test_fiber_query_source_is_tainted(tmp_path):
    graph = _scan(
        tmp_path,
        """\
package main

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string
}

func sink(cfg []byte) {
	var c Config
	yaml.Unmarshal(cfg, &c)
}

func handler(c *fiber.Ctx) error {
	q := c.Query("term")
	sink([]byte(q))
	return nil
}

func main() {
	app := fiber.New()
	app.Get("/x", handler)
	_ = app
}
""",
    )
    assert _entrypoints(graph) == {"ep:GET:/x": "fiber"}
    assert _yaml_verdict(graph, str(tmp_path)) == TAINTED


def test_fiber_bodyparser_bind_is_tainted(tmp_path):
    graph = _scan(
        tmp_path,
        """\
package main

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string
}

func sink(cfg []byte) {
	var c Config
	yaml.Unmarshal(cfg, &c)
}

func handler(c *fiber.Ctx) error {
	var cfg Config
	c.BodyParser(&cfg)
	sink([]byte(cfg.Name))
	return nil
}

func main() {
	app := fiber.New()
	app.Post("/x", handler)
	_ = app
}
""",
    )
    assert _entrypoints(graph) == {"ep:POST:/x": "fiber"}
    assert _yaml_verdict(graph, str(tmp_path)) == TAINTED


def test_fiber_constant_only_is_not_proven(tmp_path):
    # Soundness: a fiber handler that never reads a source proves nothing.
    graph = _scan(
        tmp_path,
        """\
package main

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string
}

func sink(cfg []byte) {
	var c Config
	yaml.Unmarshal(cfg, &c)
}

func handler(c *fiber.Ctx) error {
	sink([]byte("static"))
	return nil
}

func main() {
	app := fiber.New()
	app.Post("/x", handler)
	_ = app
}
""",
    )
    assert _yaml_verdict(graph, str(tmp_path)) == NOT_PROVEN
