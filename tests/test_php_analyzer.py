"""Assertions against samples/php-app for the PHP analyzer.

``scanner/analyzers/__init__.py`` now imports (and thus registers) the PHP
analyzer, so ``scan_repo`` dispatches ``.php`` files to it. The explicit
``import scanner.analyzers.php_analyzer`` below is kept as belt-and-suspenders:
it triggers the same ``@register`` decorator directly, so these tests also pass
if the package import order ever changes.

In addition to the happy-path assertions against ``samples/php-app``, the
``test_no_false_*`` cases below are regression tests for confirmed false edges /
bogus nodes the analyzer used to emit; each builds a tiny repo in ``tmp_path``.
"""

from __future__ import annotations

import os

import pytest

import scanner.analyzers.php_analyzer  # noqa: F401  (registers the analyzer)
from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "php-app",
)

RELPATH = "routes.php"
MOD_ID = f"mod:{RELPATH}"
STORE = f"fn:{RELPATH}:ImportController.store"
VALIDATE = f"fn:{RELPATH}:ImportController.validate"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


# -- dependencies (from composer.json via the manifest adapter) -------------


def test_packagist_dependencies_present(graph):
    assert graph.has_node("dep:Packagist:guzzlehttp/guzzle")
    assert graph.has_node("dep:Packagist:monolog/monolog")
    guzzle = graph.get_node("dep:Packagist:guzzlehttp/guzzle")
    monolog = graph.get_node("dep:Packagist:monolog/monolog")
    assert guzzle.attrs["version"] == "6.3.0"
    assert monolog.attrs["version"] == "1.23.0"
    assert guzzle.attrs["ecosystem"] == "Packagist"


# -- module + function nodes ------------------------------------------------


def test_module_node_and_import_records(graph):
    mod = graph.get_node(MOD_ID)
    assert mod is not None and mod.kind == "module"
    # ``use`` statements are recorded as conservative import records only.
    imports = mod.attrs["imports"]
    assert "GuzzleHttp\\Client" in imports
    assert "Monolog\\Logger" in imports


def test_no_dependency_import_edges(graph):
    # Namespaces do not map reliably to Composer packages, so the analyzer must
    # NOT guess any imports edge from a ``use`` statement.
    import_edges = [
        e for e in graph.edges if e.kind == "imports" and e.src == MOD_ID
    ]
    assert import_edges == []


def test_controller_method_function_nodes_exist(graph):
    store = graph.get_node(STORE)
    validate = graph.get_node(VALIDATE)
    assert store is not None and store.kind == "function"
    assert validate is not None and validate.kind == "function"
    assert store.attrs["is_method"] is True
    # Methods are declared by the file's module node.
    assert any(
        e.kind == "declares" and e.src == MOD_ID and e.dst == STORE
        for e in graph.edges
    )


# -- route entrypoint + handler wiring --------------------------------------


def test_import_route_wired_to_handler(graph):
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None and ep.kind == "entrypoint"
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["framework"] == "laravel"
    assert any(
        e.kind == "route_to_handler"
        and e.src == "ep:POST:/import"
        and e.dst == STORE
        for e in graph.edges
    )


# -- intra-file call edge ----------------------------------------------------


def test_intrafile_call_edge_store_to_validate(graph):
    assert any(
        e.kind == "calls" and e.src == STORE and e.dst == VALIDATE
        for e in graph.edges
    )


# -- unresolved dynamic dispatch (no edge, recorded) ------------------------


def test_dynamic_call_is_unresolved_with_no_edge(graph):
    store = graph.get_node(STORE)
    unresolved = store.attrs.get("unresolved_calls", [])
    assert "$service->run()" in unresolved
    # The dynamic call must NOT have produced any outgoing call edge from store
    # other than the sound intra-file one.
    call_targets = {
        e.dst for e in graph.edges if e.kind == "calls" and e.src == STORE
    }
    assert call_targets == {VALIDATE}


# -- regression: no false edges / bogus nodes -------------------------------


def _scan_source(tmp_path, source: str):
    """Write ``source`` as ``r.php`` in a fresh repo and return its graph."""
    (tmp_path / "r.php").write_text(source)
    return scan_repo(str(tmp_path))


def test_no_false_edge_from_anonymous_class_method(tmp_path):
    # B5: a method of an anonymous class must NOT be attributed to the enclosing
    # named class -- no ``A.helper`` node, no false ``A.run -> A.helper`` edge,
    # and the outer ``$this->helper()`` stays unresolved.
    graph = _scan_source(
        tmp_path,
        "<?php\n"
        "class A {\n"
        "  function run() { $x = new class { function helper() {} };"
        " $this->helper(); }\n"
        "  private function priv() {}\n"
        "}\n",
    )
    assert graph.get_node("fn:r.php:A.helper") is None
    assert not any(
        e.kind == "calls" and e.dst == "fn:r.php:A.helper" for e in graph.edges
    )
    run = graph.get_node("fn:r.php:A.run")
    assert run is not None
    assert "$this->helper()" in run.attrs.get("unresolved_calls", [])


def test_no_slim_entrypoint_for_non_slim_or_non_path_receiver(tmp_path):
    # S7: ``$app->verb("...")`` is a Slim route only when ``$app`` is bound to a
    # real Slim app AND the path starts with ``/``. A non-``/`` path on a real
    # Slim app, and any verb call on an unbound receiver, must emit no entrypoint.
    graph = _scan_source(
        tmp_path,
        "<?php\n"
        "$app = new \\Slim\\App();\n"
        '$app->get("config.debug", function(){});\n'
        '$app->delete("cache_key", function(){});\n'
        '$cache->get("/looks/like/a/path");\n'
        '$other->delete("cache_key");\n',
    )
    assert graph.get_node("ep:GET:config.debug") is None
    assert graph.get_node("ep:DELETE:cache_key") is None
    # The unbound ``$cache`` receiver must not become a Slim route either.
    assert graph.get_node("ep:GET:/looks/like/a/path") is None
    assert graph.nodes_of_kind("entrypoint") == []


def test_slim_route_on_bound_app_with_real_path_resolves(tmp_path):
    # Positive counterpart to S7: a genuine Slim app + ``/`` path IS an entry
    # point, with the closure handler flagged inline.
    graph = _scan_source(
        tmp_path,
        "<?php\n"
        "$app = \\Slim\\Factory\\AppFactory::create();\n"
        '$app->post("/widgets", function(){});\n',
    )
    ep = graph.get_node("ep:POST:/widgets")
    assert ep is not None and ep.attrs["framework"] == "slim"
    assert ep.attrs.get("inline_handler") is True


def test_no_calls_edge_to_abstract_or_interface_method(tmp_path):
    # S8: bodiless declarations (abstract methods, interface members) are not
    # sound call targets -- ``$this->run()`` and ``I::m()`` must stay unresolved,
    # even though the ``fn:`` nodes exist (marked abstract).
    graph = _scan_source(
        tmp_path,
        "<?php\n"
        "abstract class Base { abstract function run();"
        " function go(){ $this->run(); } }\n"
        "interface I { function m(); }\n"
        "class Impl implements I { function z(){ I::m(); } }\n",
    )
    assert not any(e.kind == "calls" for e in graph.edges)
    run = graph.get_node("fn:r.php:Base.run")
    assert run is not None and run.attrs.get("abstract") is True
    iface = graph.get_node("fn:r.php:I.m")
    assert iface is not None and iface.attrs.get("abstract") is True
    go = graph.get_node("fn:r.php:Base.go")
    assert "$this->run()" in go.attrs.get("unresolved_calls", [])
    z = graph.get_node("fn:r.php:Impl.z")
    assert "I::m()" in z.attrs.get("unresolved_calls", [])


def test_no_truncated_entrypoint_from_interpolated_path(tmp_path):
    # S11: an interpolated route path (``"/users/$id"``) must not be truncated to
    # ``/users/``. No entrypoint is emitted for it; a sibling static path still
    # resolves normally.
    graph = _scan_source(
        tmp_path,
        "<?php\n"
        'Route::get("/users/$id", \'Ctrl@show\');\n'
        'Route::get("/health", \'Ctrl@health\');\n',
    )
    assert graph.get_node("ep:GET:/users/") is None
    assert not any(
        n.attrs.get("path") == "/users/" for n in graph.nodes_of_kind("entrypoint")
    )
    # The static sibling route is unaffected.
    assert graph.get_node("ep:GET:/health") is not None
