"""Registry-style Python route detection (Flask-RESTful + imperative + prefix).

These scan ``samples/flask-restful-app`` once and assert that the analyzer now
finds routes registered by a *call* rather than a decorator -- the pattern that
previously left apps like redash at zero entry points -- while never fabricating
a route for a dynamic path or an unrecognised receiver.
"""

from __future__ import annotations

import os
import textwrap

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


# -- Regression tests for confirmed route-detection bugs ----------------------
#
# Each builds a tiny throwaway repo and asserts the analyzer stays sound: it
# records what it cannot resolve rather than fabricating a route, path, or verb.


def _scan_tmp(tmp_path, files: dict[str, str]):
    for name, src in files.items():
        (tmp_path / name).write_text(textwrap.dedent(src).lstrip())
    return scan_repo(str(tmp_path))


def _unresolved_routes(graph) -> list[str]:
    notes: list[str] = []
    for mod in graph.nodes_of_kind("module"):
        notes.extend(mod.attrs.get("unresolved_routes", []))
    return notes


def test_imported_app_decorator_recorded_not_emitted(tmp_path):
    # ``@app.route("/imported")`` where ``app`` is imported (factory/blueprint
    # layout), so the receiver isn't a recognised, in-file app/router.
    graph = _scan_tmp(
        tmp_path,
        {
            "views.py": """
                from myapp import app

                @app.route("/imported")
                def handler():
                    return "x"
            """,
        },
    )
    assert graph.get_node("ep:GET:/imported") is None
    notes = _unresolved_routes(graph)
    assert any("/imported" in n for n in notes), notes


def test_inherited_verb_resource_recorded_no_invented_verb(tmp_path):
    # UserResource inherits ``post`` from a repo-local base. The verb must NOT be
    # invented as an entrypoint; the ambiguity is recorded instead.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from flask import Flask
                from flask_restful import Api, Resource

                app = Flask(__name__)
                api = Api(app)

                class BaseResource(Resource):
                    def post(self, id):
                        return {}

                class UserResource(BaseResource):
                    pass

                api.add_resource(UserResource, "/users/<id>")
            """,
        },
    )
    assert graph.get_node("ep:POST:/users/<id>") is None
    assert graph.get_node("ep:GET:/users/<id>") is None
    notes = _unresolved_routes(graph)
    assert any("UserResource" in n and "inherit" in n.lower() for n in notes), notes


def test_set_literal_methods_yields_post_not_get(tmp_path):
    # methods={"POST"} (a set literal) must register POST, not fall back to GET.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from flask import Flask

                app = Flask(__name__)

                def submit():
                    return "ok"

                app.add_url_rule("/submit", view_func=submit, methods={"POST"})
            """,
        },
    )
    assert graph.get_node("ep:POST:/submit") is not None
    assert graph.get_node("ep:GET:/submit") is None


def test_as_view_honours_explicit_methods(tmp_path):
    # as_view with an explicit methods= must intersect with the class verbs:
    # only POST, even though the class also defines get.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from flask import Flask

                app = Flask(__name__)

                class V:
                    def get(self):
                        return "g"

                    def post(self):
                        return "p"

                app.add_url_rule("/v", view_func=V.as_view("v"), methods=["POST"])
            """,
        },
    )
    assert graph.get_node("ep:POST:/v") is not None
    assert graph.get_node("ep:GET:/v") is None


def test_remove_resource_yields_no_entrypoint(tmp_path):
    # api.remove_resource(...) is not a registration -- no route may be emitted.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from flask import Flask
                from flask_restful import Api, Resource

                app = Flask(__name__)
                api = Api(app)

                class Thing(Resource):
                    def get(self):
                        return {}

                api.remove_resource(Thing, "/gone")
            """,
        },
    )
    assert graph.get_node("ep:GET:/gone") is None
    assert graph.nodes_of_kind("entrypoint") == []


def test_none_mount_prefix_keeps_ctor_prefix(tmp_path):
    # register_blueprint(bp, url_prefix=None) must NOT drop the blueprint's own
    # constructor url_prefix.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                from flask import Flask, Blueprint

                bp = Blueprint("bp", __name__, url_prefix="/api")
                app = Flask(__name__)

                @bp.route("/x")
                def x():
                    return "x"

                app.register_blueprint(bp, url_prefix=None)
            """,
        },
    )
    ep = graph.get_node("ep:GET:/api/x")
    assert ep is not None
    assert ep.attrs.get("prefix_unresolved") is not True
    assert graph.get_node("ep:GET:/x") is None


def test_cross_file_router_mount_flags_prefix_unresolved(tmp_path):
    # The include_router mount (with its prefix) lives in another file, so the
    # full prefix can't be seen: emit the in-file ctor path and flag it, never
    # the wrong full path, never a silent truncation.
    graph = _scan_tmp(
        tmp_path,
        {
            "routes.py": """
                from fastapi import APIRouter

                router = APIRouter(prefix="/v1")

                @router.get("/items")
                def items():
                    return []
            """,
            "main.py": """
                from fastapi import FastAPI
                from routes import router

                app = FastAPI()
                app.include_router(router, prefix="/api")
            """,
        },
    )
    ep = graph.get_node("ep:GET:/v1/items")
    assert ep is not None
    assert ep.attrs.get("prefix_unresolved") is True
    # The (unknowable) full cross-file path must NOT be fabricated.
    assert graph.get_node("ep:GET:/api/v1/items") is None


def test_non_literal_extra_path_arg_recorded(tmp_path):
    # add_resource(Cls, "/thing", dyn) -- the literal path is emitted, the
    # dynamic one is recorded rather than silently dropped.
    graph = _scan_tmp(
        tmp_path,
        {
            "app.py": """
                import os
                from flask import Flask
                from flask_restful import Api, Resource

                app = Flask(__name__)
                api = Api(app)
                alt = os.environ["ALT"]

                class Thing(Resource):
                    def get(self):
                        return {}

                api.add_resource(Thing, "/thing", alt)
            """,
        },
    )
    assert graph.get_node("ep:GET:/thing") is not None
    notes = _unresolved_routes(graph)
    assert any("Thing" in n and "non-literal" in n.lower() for n in notes), notes
