"""Sound cross-PACKAGE Go resolution, against samples/go-multipkg-app plus
focused negatives over inline multi-package fixtures built under ``tmp_path``.

The sample is a tiny multi-package Gin app:

    main.go                 r := gin.Default()
                            r.POST("/import", handlers.Import)   (cross-pkg handler)
    handlers/handlers.go    package handlers; Import calls config.Load  (cross-pkg)
    config/config.go        package config;   Load calls yaml.Unmarshal (external dep)

So the chain  POST /import -> Import -> Load -> yaml  crosses two package
boundaries before reaching the external dependency.

These tests assert the POSITIVE cross-package edges, that the old yaml dep is
reachable through that chain, and the NEGATIVES the cardinal rule requires: a
non-local import stays an external dep (never cross-file); a local import of a
package directory that does not exist, an unexported or absent exported name,
and a package-name/directory-name mismatch each fabricate NO edge (and are
recorded, so the assertions are not vacuous).
"""

from __future__ import annotations

import os

import pytest

# Import triggers @register so analyzer_for("go") resolves.
import scanner.analyzers.go_analyzer  # noqa: F401
from scanner.reachability import REACHABLE, compute_reachability
from scanner.scan import scan_repo

MULTI_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "go-multipkg-app",
)

GIN = "dep:Go:github.com/gin-gonic/gin"
YAML = "dep:Go:gopkg.in/yaml.v2"

IMPORT_FN = "fn:handlers/handlers.go:Import"
LOAD_FN = "fn:config/config.go:Load"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(MULTI_APP)


def _edges(graph, kind):
    return [e for e in graph.edges if e.kind == kind]


def _has_edge(graph, src, dst, kind):
    return any(e.src == src and e.dst == dst and e.kind == kind for e in graph.edges)


# -- positive: cross-package route handler -----------------------------------


def test_cross_package_route_to_handler(graph):
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"
    # The handler reference `handlers.Import` resolved into the local handlers
    # package, recording the selector text and the file the target lives in.
    assert ep.attrs.get("handler") == "handlers.Import"
    assert ep.attrs.get("handler_file") == "handlers/handlers.go"
    assert ep.attrs.get("unresolved_handler") is None
    assert _has_edge(graph, "ep:POST:/import", IMPORT_FN, "route_to_handler")


# -- positive: cross-package call edge ---------------------------------------


def test_cross_package_call_edge_import_to_load(graph):
    # Import calls config.Load, where config is a local package binding and Load
    # is its single exported function: a cross-package `calls` edge.
    assert _has_edge(graph, IMPORT_FN, LOAD_FN, "calls")


# -- positive: external dep reachable through the cross-package chain ---------


def test_yaml_reachable_through_cross_package_chain(graph):
    # Load -> yaml.Unmarshal directly, with yaml imported in the config package.
    yaml_calls = [
        e for e in _edges(graph, "calls") if e.dst == YAML and e.src == LOAD_FN
    ]
    assert len(yaml_calls) == 1
    assert yaml_calls[0].attrs.get("symbol") == "yaml.Unmarshal"
    result = compute_reachability(graph)
    # POST /import reaches yaml only through the resolved cross-package
    # route_to_handler + calls edges.
    assert result.repo.verdict_by_dep.get(YAML) == REACHABLE
    assert YAML in {d["id"] for d in result.repo.reachable_deps}


# -- negative: a non-local import stays an external dep, never cross-file -----


def test_non_local_import_stays_dependency(graph):
    # gin is NOT under the module path, so it remains an external dependency:
    # an `imports` edge and a dependency `calls` edge, never a cross-file fn.
    assert _has_edge(graph, "mod:main.go", GIN, "imports")
    gin_calls = [
        e
        for e in _edges(graph, "calls")
        if e.dst == GIN and e.src == "fn:main.go:main"
    ]
    assert gin_calls, "gin.Default not recorded as a dependency call"
    assert any("gin.Default" == str(e.attrs.get("symbol", "")) for e in gin_calls)
    # No function node is ever fabricated for the gin package.
    assert not any(n.id.startswith("fn:") and "gin" in n.id for n in graph.nodes)


# ---------------------------------------------------------------------------
# Negatives over inline multi-package fixtures (cardinal rule: no false edge).
# ---------------------------------------------------------------------------


def _scan_multi(tmp_path, module, files, requires=()):
    """Write a multi-package Go repo (go.mod + files) under tmp_path and scan it."""
    req_block = ""
    if requires:
        lines = "\n".join(f"\t{mod} {ver}" for mod, ver in requires)
        req_block = f"\nrequire (\n{lines}\n)\n"
    (tmp_path / "go.mod").write_text(f"module {module}\n\ngo 1.19\n" + req_block)
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return scan_repo(str(tmp_path))


def _calls_from(graph, src):
    return [e.dst for e in graph.edges if e.kind == "calls" and e.src == src]


def test_local_import_of_missing_package_no_edge_recorded(tmp_path):
    # A local import whose package directory does not exist in the repo resolves
    # to nothing: the call stays unresolved and the import is recorded.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {"main.go": 'package main\nimport "example.com/app/missing"\nfunc main() { missing.Do() }\n'},
    )
    main = graph.get_node("fn:main.go:main")
    assert main is not None
    assert "missing.Do" in main.attrs.get("unresolved_calls", [])
    mod = graph.get_node("mod:main.go")
    assert "example.com/app/missing" in mod.attrs.get("unresolved_local_imports", [])
    # No calls edge to any fabricated function node.
    assert not any(d.startswith("fn:") for d in _calls_from(graph, "fn:main.go:main"))


def test_unexported_and_absent_names_no_edge(tmp_path):
    # Only the single EXACTLY-ONE exported name resolves; an unexported name and
    # an absent name each stay unresolved with no edge.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": 'package main\nimport "example.com/app/sub"\nfunc main() { sub.Pub(); sub.priv(); sub.Absent() }\n',
            "sub/sub.go": "package sub\nfunc Pub() {}\nfunc priv() {}\n",
        },
    )
    main = graph.get_node("fn:main.go:main")
    unresolved = main.attrs.get("unresolved_calls", [])
    assert "sub.priv" in unresolved  # unexported -> not in the export index
    assert "sub.Absent" in unresolved  # absent name
    # The exported name resolves to exactly one function; the others do not.
    assert _calls_from(graph, "fn:main.go:main") == ["fn:sub/sub.go:Pub"]


def test_package_name_directory_mismatch_no_edge(tmp_path):
    # Directory `foo` but `package bar` with no alias: the last-segment binding
    # name `foo` does not match the declared package, so it is left unresolved.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": 'package main\nimport "example.com/app/foo"\nfunc main() { foo.X() }\n',
            "foo/foo.go": "package bar\nfunc X() {}\n",
        },
    )
    main = graph.get_node("fn:main.go:main")
    assert "foo.X" in main.attrs.get("unresolved_calls", [])
    mod = graph.get_node("mod:main.go")
    assert "example.com/app/foo" in mod.attrs.get("unresolved_local_imports", [])
    assert _calls_from(graph, "fn:main.go:main") == []


def test_alias_resolves_despite_directory_mismatch(tmp_path):
    # With an explicit alias matching the declared package name, Go binds to the
    # package regardless of its directory, so the call resolves soundly.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": 'package main\nimport bar "example.com/app/foo"\nfunc main() { bar.X() }\n',
            "foo/foo.go": "package bar\nfunc X() {}\n",
        },
    )
    assert _calls_from(graph, "fn:main.go:main") == ["fn:foo/foo.go:X"]


def test_nested_declared_module_is_external_not_local(tmp_path):
    # Regression (#6): a separately-published module nested UNDER the main module
    # path -- main module `example.com/app`, a DECLARED dependency
    # `example.com/app/v2` -- must classify as an EXTERNAL dependency, not a
    # local package. Before the fix the "under the module path" test ran first,
    # so `example.com/app/v2` was treated as local, found no package directory,
    # and was dropped into unresolved_local_imports, losing its dep edges and
    # forcing a weaker reachability verdict.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": (
                "package main\n"
                'import v2 "example.com/app/v2"\n'
                "func main() { v2.Do() }\n"
            ),
        },
        requires=(("example.com/app/v2", "v2.0.0"),),
    )
    v2_dep = "dep:Go:example.com/app/v2"
    # The nested module resolves to its declared dependency node (external): an
    # `imports` edge from the module and a dependency `calls` edge carrying the
    # selector -- never a fabricated local function.
    assert _has_edge(graph, "mod:main.go", v2_dep, "imports")
    v2_calls = [
        e
        for e in graph.edges
        if e.kind == "calls" and e.dst == v2_dep and e.src == "fn:main.go:main"
    ]
    assert len(v2_calls) == 1
    assert v2_calls[0].attrs.get("symbol") == "v2.Do"
    # It is NOT dropped as an unresolvable local import, and no local function
    # node is fabricated for it.
    mod = graph.get_node("mod:main.go")
    assert "example.com/app/v2" not in mod.attrs.get("unresolved_local_imports", [])
    assert not any(n.id.startswith("fn:") and "/v2" in n.id for n in graph.nodes)


def test_genuinely_local_subpackage_still_resolves_cross_package(tmp_path):
    # A real subpackage under the module path that is NOT a declared dependency
    # must still resolve cross-package to its exported function (the fix must not
    # regress genuinely-local resolution).
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": (
                "package main\n"
                'import "example.com/app/internal/foo"\n'
                "func main() { foo.Do() }\n"
            ),
            "internal/foo/foo.go": "package foo\nfunc Do() {}\n",
        },
    )
    assert _calls_from(graph, "fn:main.go:main") == ["fn:internal/foo/foo.go:Do"]
    mod = graph.get_node("mod:main.go")
    assert "example.com/app/internal/foo" not in mod.attrs.get(
        "unresolved_local_imports", []
    )


def test_prefix_neighbor_dep_stays_external(tmp_path):
    # A declared dependency that merely shares a string prefix with the main
    # module path but is NOT nested under it -- `example.com/app-utils` next to
    # module `example.com/app` -- is external and unaffected by the nested-module
    # reclassification (it is not under `example.com/app/`).
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": (
                "package main\n"
                'import "example.com/app-utils"\n'
                "func main() { apputils.Do() }\n"
            ),
        },
        requires=(("example.com/app-utils", "v1.0.0"),),
    )
    utils_dep = "dep:Go:example.com/app-utils"
    assert _has_edge(graph, "mod:main.go", utils_dep, "imports")
    mod = graph.get_node("mod:main.go")
    assert "example.com/app-utils" not in mod.attrs.get("unresolved_local_imports", [])
    # Not misclassified as local: no fabricated local function node for it.
    assert not any(n.id.startswith("fn:") and "app-utils" in n.id for n in graph.nodes)


def test_dot_and_blank_imports_never_resolve(tmp_path):
    # Dot and blank imports bind no usable name; a bare call that could only come
    # from a dot-import target stays unresolved, and both imports are recorded.
    graph = _scan_multi(
        tmp_path,
        "example.com/app",
        {
            "main.go": (
                "package main\n"
                'import (\n\t. "example.com/app/sub"\n\t_ "example.com/app/side"\n)\n'
                "func main() { Pub() }\n"
            ),
            "sub/sub.go": "package sub\nfunc Pub() {}\n",
            "side/side.go": "package side\nfunc Init() {}\n",
        },
    )
    main = graph.get_node("fn:main.go:main")
    # `Pub` is a bare name not declared in main.go -> unresolved (dot-import is
    # never followed), no fabricated edge.
    assert "Pub" in main.attrs.get("unresolved_calls", [])
    assert _calls_from(graph, "fn:main.go:main") == []
    mod = graph.get_node("mod:main.go")
    recorded = mod.attrs.get("unresolved_local_imports", [])
    assert "example.com/app/sub" in recorded
    assert "example.com/app/side" in recorded
