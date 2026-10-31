"""Sound SAME-package cross-file Go resolution, against samples/go-samepkg-app
plus focused soundness negatives over inline fixtures under ``tmp_path``.

In Go a package is a directory, so a top-level function declared in one file is
callable as a BARE name (no import, no qualifier) from any other file of the
same directory. The sample is a single ``package main`` split across files:

    main.go     r.POST("/import", importHandler)          bare handler -> handler.go
    handler.go  importHandler: data := c.PostForm(...); parseConfig(data)  bare -> parse.go
    parse.go    parseConfig(data): yaml.Unmarshal([]byte(data), &cfg)      external dep sink

So the chain  POST /import -> importHandler -> parseConfig -> yaml.Unmarshal
crosses TWO file boundaries within the SAME package, using only bare names.

These tests assert the POSITIVE same-package cross-file edges (a bare handler
and a bare call both resolving across files of one directory), that yaml is
reachable AND tainted through that chain, and the SOUNDNESS NEGATIVES the
cardinal rule requires: a bare name shadowed by a local binding is NOT resolved
to the package function (no spurious edge, no false taint), and a bare name
that matches no same-directory function stays unresolved. Everything is offline
and deterministic.
"""

from __future__ import annotations

import os
import textwrap

import pytest

# Import triggers @register so analyzer_for("go") resolves.
import scanner.analyzers.go_analyzer  # noqa: F401
from scanner.reachability import REACHABLE, compute_reachability
from scanner.scan import scan_repo
from scanner.taint import NOT_PROVEN, TAINTED, compute_taint

SAMEPKG_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "go-samepkg-app",
)

YAML = "dep:Go:gopkg.in/yaml.v2"

HANDLER_FN = "fn:handler.go:importHandler"
PARSE_FN = "fn:parse.go:parseConfig"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMEPKG_APP)


def _edges(graph, kind):
    return [e for e in graph.edges if e.kind == kind]


def _has_edge(graph, src, dst, kind):
    return any(e.src == src and e.dst == dst and e.kind == kind for e in graph.edges)


def _file_of(fn_id):
    # fn:<relpath>:<qual>
    return fn_id[len("fn:"):].rsplit(":", 1)[0]


# -- positive: same-package cross-file bare handler + bare call ---------------


def test_cross_file_bare_handler_resolves(graph):
    # The route handler `importHandler` is a BARE name whose declaration lives
    # in handler.go, a DIFFERENT file from main.go (same directory / package).
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"
    assert ep.attrs.get("handler") == "importHandler"
    assert ep.attrs.get("handler_file") == "handler.go"
    assert ep.attrs.get("unresolved_handler") is None
    assert _has_edge(graph, "ep:POST:/import", HANDLER_FN, "route_to_handler")


def test_cross_file_bare_call_resolves(graph):
    # importHandler (handler.go) calls parseConfig (parse.go) by bare name: a
    # same-package `calls` edge whose endpoints are in DIFFERENT files.
    assert _has_edge(graph, HANDLER_FN, PARSE_FN, "calls")
    assert _file_of(HANDLER_FN) != _file_of(PARSE_FN)
    # And the call was not recorded as unresolved on the caller.
    caller = graph.get_node(HANDLER_FN)
    assert "parseConfig" not in caller.attrs.get("unresolved_calls", [])


# -- positive: reachability through the cross-file chain ----------------------


def test_yaml_reachable_through_cross_file_chain(graph):
    # parseConfig -> yaml.Unmarshal directly; the only route into parseConfig is
    # the bare same-package cross-file chain from the route handler.
    yaml_calls = [
        e for e in _edges(graph, "calls") if e.dst == YAML and e.src == PARSE_FN
    ]
    assert len(yaml_calls) == 1
    assert yaml_calls[0].attrs.get("symbol") == "yaml.Unmarshal"
    result = compute_reachability(graph)
    assert result.repo.verdict_by_dep.get(YAML) == REACHABLE
    assert YAML in {d["id"] for d in result.repo.reachable_deps}


# -- positive: taint through the cross-file chain -----------------------------


def test_yaml_tainted_through_cross_file_chain(graph):
    reach = compute_reachability(graph)
    result = compute_taint(graph, reach, os.path.abspath(SAMEPKG_APP))[YAML]
    assert result.verdict == TAINTED
    assert result.source == "c.PostForm"
    assert result.sink_symbol == "yaml.Unmarshal"
    assert result.entrypoint == "POST /import"
    # The proven path spans the MULTIPLE files of the one package.
    assert result.path == [
        "ep:POST:/import",
        HANDLER_FN,
        PARSE_FN,
        YAML,
    ]
    assert _file_of(result.path[1]) != _file_of(result.path[2])


# ---------------------------------------------------------------------------
# Soundness negatives over inline fixtures (cardinal rule: no false edge).
# ---------------------------------------------------------------------------


def _scan(tmp_path, files, requires=()):
    req_block = ""
    if requires:
        lines = "\n".join(f"\t{mod} {ver}" for mod, ver in requires)
        req_block = f"\nrequire (\n{lines}\n)\n"
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.19\n" + req_block
    )
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return scan_repo(str(tmp_path))


def _calls_from(graph, src):
    return [e.dst for e in graph.edges if e.kind == "calls" and e.src == src]


def test_shadowed_bare_name_not_resolved(tmp_path):
    # parseConfig is a package func (parse.go), but caller() in handler.go binds
    # a LOCAL name `parseConfig` that shadows it. The existing `bound`-shadow
    # guard runs FIRST, so the bare call must NOT resolve to the package func --
    # it stays unresolved with no fabricated cross-file edge.
    graph = _scan(
        tmp_path,
        {
            "handler.go": """
                package main
                func caller() {
                	parseConfig := "x"
                	_ = parseConfig
                	parseConfig("y")
                }
                """,
            "parse.go": "package main\nfunc parseConfig(data string) {}\n",
        },
    )
    caller = graph.get_node("fn:handler.go:caller")
    assert caller is not None
    assert "fn:parse.go:parseConfig" not in _calls_from(graph, "fn:handler.go:caller")
    assert "parseConfig" in caller.attrs.get("unresolved_calls", [])


def test_shadowed_handler_bare_name_produces_no_false_taint(tmp_path):
    # The same-package fixture shape, but importHandler SHADOWS parseConfig with
    # a local binding. The bare call does not resolve across files, so the yaml
    # sink is never reached from the route -> no false taint (not_proven).
    graph = _scan(
        tmp_path,
        {
            "main.go": """
                package main
                import "github.com/gin-gonic/gin"
                func main() {
                	r := gin.Default()
                	r.POST("/import", importHandler)
                	_ = r
                }
                """,
            "handler.go": """
                package main
                import "github.com/gin-gonic/gin"
                func importHandler(c *gin.Context) {
                	data := c.PostForm("data")
                	parseConfig := data
                	_ = parseConfig
                	parseConfig(data)
                }
                """,
            "parse.go": """
                package main
                import "gopkg.in/yaml.v2"
                type Config struct{ Name string }
                func parseConfig(data string) {
                	var c Config
                	yaml.Unmarshal([]byte(data), &c)
                }
                """,
        },
        requires=(
            ("github.com/gin-gonic/gin", "v1.6.0"),
            ("gopkg.in/yaml.v2", "v2.2.2"),
        ),
    )
    # The bare handler call is shadowed in importHandler -> no cross-file edge.
    assert "fn:parse.go:parseConfig" not in _calls_from(
        graph, "fn:handler.go:importHandler"
    )
    # With no edge into parseConfig, yaml is never reached from the route, so
    # there can be no false taint: absent from the result, or at worst
    # not_proven -- never TAINTED.
    reach = compute_reachability(graph)
    assert reach.repo.verdict_by_dep.get(YAML) != REACHABLE
    taint = compute_taint(graph, reach, str(tmp_path))
    assert YAML not in taint or taint[YAML].verdict == NOT_PROVEN


def test_unknown_bare_name_stays_unresolved(tmp_path):
    # A bare name that matches NO top-level func in the same directory stays
    # unresolved -- never a fabricated edge.
    graph = _scan(
        tmp_path,
        {
            "a.go": 'package main\nfunc caller() { doesNotExist("y") }\n',
            "b.go": "package main\nfunc other() {}\n",
        },
    )
    caller = graph.get_node("fn:a.go:caller")
    assert caller is not None
    assert _calls_from(graph, "fn:a.go:caller") == []
    assert "doesNotExist" in caller.attrs.get("unresolved_calls", [])


def test_ambiguous_name_across_files_dropped(tmp_path):
    # If (hypothetically) the same top-level name were declared in >1 file of the
    # dir -- impossible in compilable Go, but we must never emit a wrong edge --
    # the name is dropped from the index, so a bare call to it stays unresolved.
    graph = _scan(
        tmp_path,
        {
            "a.go": "package main\nfunc dup() {}\n",
            "b.go": "package main\nfunc dup() {}\n",
            "caller.go": "package main\nfunc caller() { dup() }\n",
        },
    )
    caller = graph.get_node("fn:caller.go:caller")
    assert caller is not None
    # Ambiguous -> omitted from the same-package map -> no resolution.
    assert _calls_from(graph, "fn:caller.go:caller") == []
    assert "dup" in caller.attrs.get("unresolved_calls", [])
