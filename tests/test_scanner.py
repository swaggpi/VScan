"""End-to-end assertions against samples/vulnerable-app."""

from __future__ import annotations

import json

from scanner.graph import KnowledgeGraph


def _deps_by_ecosystem(graph, ecosystem):
    return {
        n.name: n
        for n in graph.nodes_of_kind("dependency")
        if n.attrs.get("ecosystem") == ecosystem
    }


# -- dependencies across all four ecosystems --------------------------------


def test_python_dependencies(graph):
    deps = _deps_by_ecosystem(graph, "PyPI")
    assert deps["Flask"].attrs["version"] == "0.12.2"
    assert deps["Jinja2"].attrs["version"] == "2.10"
    assert deps["PyYAML"].attrs["version"] == "3.13"
    # requirements versions are declared (==/>= pins), never lockfile-resolved.
    assert deps["Flask"].attrs["resolved"] is False
    # -r include was followed.
    assert "urllib3" in deps
    assert deps["urllib3"].attrs["version"] == "1.24.1"


def test_javascript_dependencies_resolved_from_lockfile(graph):
    deps = _deps_by_ecosystem(graph, "npm")
    assert deps["lodash"].attrs["version"] == "4.17.4"
    assert deps["lodash"].attrs["resolved"] is True
    assert deps["lodash"].attrs["declared"] == "^4.17.4"
    assert deps["minimist"].attrs["version"] == "1.2.0"
    assert deps["minimist"].attrs["resolved"] is True


def test_php_dependencies(graph):
    deps = _deps_by_ecosystem(graph, "Packagist")
    assert deps["monolog/monolog"].attrs["version"] == "1.23.0"
    assert deps["guzzlehttp/guzzle"].attrs["version"] == "6.3.0"
    assert deps["phpunit/phpunit"].attrs["version"] == "6.5.0"
    # The platform requirement "php" must not be emitted as a dependency.
    assert "php" not in deps


def test_go_dependencies(graph):
    deps = _deps_by_ecosystem(graph, "Go")
    assert deps["github.com/gin-gonic/gin"].attrs["version"] == "v1.6.0"
    assert deps["gopkg.in/yaml.v2"].attrs["version"] == "v2.2.2"


def test_declares_edge_from_manifest(graph):
    edges = [
        e
        for e in graph.edges
        if e.kind == "declares" and e.dst == "dep:PyPI:Flask"
    ]
    assert any(e.src == "file:requirements.txt" for e in edges)


# -- entry point + route wiring ---------------------------------------------


def test_import_entrypoint_exists_with_handler_edge(graph):
    ep = graph.get_node("ep:POST:/import")
    assert ep is not None
    assert ep.attrs["method"] == "POST"
    assert ep.attrs["path"] == "/import"

    route_edges = [
        e
        for e in graph.edges
        if e.kind == "route_to_handler" and e.src == "ep:POST:/import"
    ]
    assert route_edges, "no route_to_handler edge from /import"
    assert route_edges[0].dst == "fn:app.py:import_data"


def test_health_entrypoint_defaults_to_get(graph):
    ep = graph.get_node("ep:GET:/health")
    assert ep is not None
    assert ep.attrs["method"] == "GET"


# -- resolved call chain reaching PyYAML through the aliased import ----------


def test_call_chain_reaches_pyyaml_via_alias(graph):
    # import_data -> load_config (intra-repo call edge)
    assert any(
        e.kind == "calls"
        and e.src == "fn:app.py:import_data"
        and e.dst == "fn:utils/config_loader.py:load_config"
        for e in graph.edges
    ), "missing import_data -> load_config call edge"

    # load_config -> PyYAML dependency, with the aliased symbol resolved.
    yaml_calls = [
        e
        for e in graph.edges
        if e.kind == "calls"
        and e.src == "fn:utils/config_loader.py:load_config"
        and e.dst == "dep:PyPI:PyYAML"
    ]
    assert yaml_calls, "missing load_config -> PyYAML call edge"
    assert "load" in yaml_calls[0].attrs.get("symbol", "")


def test_import_edge_module_to_dependency(graph):
    assert any(
        e.kind == "imports"
        and e.src == "mod:utils.config_loader"
        and e.dst == "dep:PyPI:PyYAML"
        for e in graph.edges
    )


def test_import_edge_intra_repo(graph):
    assert any(
        e.kind == "imports"
        and e.src == "mod:app"
        and e.dst == "mod:utils.config_loader"
        for e in graph.edges
    )


# -- documentation links -----------------------------------------------------


def test_readme_documents_import_entrypoint(graph):
    assert any(
        e.kind == "documents"
        and e.src == "doc:README.md"
        and e.dst == "ep:POST:/import"
        for e in graph.edges
    ), "README should document the /import entrypoint"


def test_openapi_spec_ingested_as_doc(graph):
    doc = graph.get_node("doc:docs/openapi.yaml")
    assert doc is not None
    assert doc.attrs.get("kind_hint") == "openapi"


# -- serialization -----------------------------------------------------------


def test_to_json_round_trips(graph):
    text = graph.to_json()
    data = json.loads(text)
    assert set(data.keys()) == {"version", "nodes", "edges", "summary"}

    # Rebuild a graph from the serialized nodes/edges and re-serialize: the
    # node and edge sets must be identical.
    rebuilt = KnowledgeGraph()
    for node in data["nodes"]:
        rebuilt.add_node(node["id"], node["kind"], node["name"], **node["attrs"])
    for edge in data["edges"]:
        rebuilt.add_edge(edge["src"], edge["dst"], edge["kind"], **edge["attrs"])

    rebuilt_data = json.loads(rebuilt.to_json())
    assert rebuilt_data["nodes"] == data["nodes"]
    assert rebuilt_data["edges"] == data["edges"]


def test_summary_counts_present(graph):
    summary = graph.summary()
    assert summary["node_counts"]["dependency"] == len(summary["dependencies"])
    assert summary["node_counts"]["file"] > 0
    assert summary["node_counts"]["function"] > 0
    assert summary["edge_counts"]["route_to_handler"] >= 1
