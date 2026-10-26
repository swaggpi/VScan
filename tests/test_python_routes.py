"""Registry-style Python route detection (Flask-RESTful + imperative + prefix).

These scan ``samples/flask-restful-app`` once and assert that the analyzer now
finds routes registered by a *call* rather than a decorator -- the pattern that
previously left apps like redash at zero entry points -- while never fabricating
a route for a dynamic path or an unrecognised receiver.
"""

from __future__ import annotations

import os

import pytest

from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "flask-restful-app",
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


# -- Flask-RESTful add_resource (the redash case) -----------------------------


def test_add_resource_emits_get_route_with_cross_file_handler(graph):
    ep = graph.get_node("ep:GET:/users/<id>")
    assert ep is not None, "add_resource GET route not detected"
    assert ep.attrs.get("framework") == "flask-restful"
    assert ep.attrs.get("handler") == "UserResource.get"
    assert ep.attrs.get("handler_file") == "resources.py"
    assert "fn:resources.py:UserResource.get" in _routed_to(graph, "ep:GET:/users/<id>")


def test_add_resource_emits_post_route_with_cross_file_handler(graph):
    ep = graph.get_node("ep:POST:/users/<id>")
    assert ep is not None, "add_resource POST route not detected"
    assert ep.attrs.get("framework") == "flask-restful"
    assert "fn:resources.py:UserResource.post" in _routed_to(
        graph, "ep:POST:/users/<id>"
    )


def test_add_resource_only_emits_verbs_defined_on_the_class(graph):
    # UserResource defines only get + post -- no PUT/DELETE/etc. invented.
    for verb in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        assert graph.get_node(f"ep:{verb}:/users/<id>") is None, (
            f"invented a {verb} route the Resource class never defines"
        )


# -- Imperative add_url_rule --------------------------------------------------


def test_add_url_rule_emits_route_and_resolves_function_handler(graph):
    ep = graph.get_node("ep:GET:/health")
    assert ep is not None, "add_url_rule route not detected"
    assert ep.attrs.get("framework") == "flask"
    assert "fn:blueprints.py:health_view" in _routed_to(graph, "ep:GET:/health")


# -- Blueprint url_prefix composition -----------------------------------------


def test_blueprint_route_gets_composed_prefix(graph):
    # @widgets_bp.route("/widgets") on a Blueprint(url_prefix="/api/v1").
    ep = graph.get_node("ep:GET:/api/v1/widgets")
    assert ep is not None, "blueprint url_prefix was not composed onto the route"
    assert ep.attrs.get("framework") == "flask"
    assert "fn:blueprints.py:list_widgets" in _routed_to(
        graph, "ep:GET:/api/v1/widgets"
    )
    # The un-prefixed local path must NOT also exist.
    assert graph.get_node("ep:GET:/widgets") is None


# -- Cardinal rule: negatives -------------------------------------------------


def test_non_literal_path_yields_no_entrypoint(graph):
    # api.add_resource(SecretResource, _dynamic_path) -- dynamic path.
    assert graph.get_node("ep:GET:/secret") is None
    for e in graph.edges:
        if e.kind == "route_to_handler":
            assert e.dst != "fn:resources.py:SecretResource.get", (
                "emitted a route for a Resource registered with a dynamic path"
            )
    # The unresolved registration is recorded rather than silently dropped.
    mod = graph.get_node("mod:app")
    assert mod is not None
    notes = mod.attrs.get("unresolved_routes", [])
    assert any("SecretResource" in note for note in notes)


def test_non_api_receiver_yields_no_entrypoint(graph):
    # not_api.add_resource(UserResource, "/should-not-appear") -- receiver is
    # not a Flask-RESTful Api instance, so no route may be emitted.
    assert graph.get_node("ep:GET:/should-not-appear") is None
    assert graph.get_node("ep:ANY:/should-not-appear") is None
