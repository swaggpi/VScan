"""Negative / edge-case coverage for the Python analyzer and walker.

These build a tiny throwaway repository under ``tmp_path`` and assert the
properties that the sample app does not exercise: that a locally-shadowed import
produces NO dependency edge, that method dispatch stays unresolved, that an
unparsable file does not abort the scan, that Django/FastAPI routes are wired,
and that a ``.gitignore``d file never reaches the graph.
"""

from __future__ import annotations

import os

import pytest

from scanner.scan import scan_repo


def _write(root: str, relpath: str, content: str) -> None:
    abspath = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(abspath), exist_ok=True)
    with open(abspath, "w", encoding="utf-8") as handle:
        handle.write(content)


@pytest.fixture(scope="module")
def neg_graph(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("neg_repo"))

    # PyYAML must be a known dependency so a *false* yaml edge is even possible;
    # that is exactly what the shadowing fix must prevent.
    _write(root, "requirements.txt", "PyYAML==3.13\n")

    # A parameter named ``y`` shadows ``import yaml as y`` inside f; ``g`` and
    # ``C.method`` perform method dispatch that cannot be resolved.
    _write(
        root,
        "shadow.py",
        "import yaml as y\n"
        "\n"
        "\n"
        "def f(y):\n"
        "    return y.load(1)\n"
        "\n"
        "\n"
        "def g(obj):\n"
        "    obj.method()\n"
        "\n"
        "\n"
        "class C:\n"
        "    def method(self):\n"
        "        return self.helper()\n",
    )

    # A genuinely unparsable file: the scan must still complete.
    _write(root, "broken.py", "def broken(:\n    pass\n")

    # Django URLconf.
    _write(
        root,
        "urls.py",
        "from django.urls import path\n"
        "from views import home\n"
        "\n"
        "urlpatterns = [\n"
        "    path('home/', home),\n"
        "]\n",
    )
    _write(root, "views.py", "def home(request):\n    return None\n")

    # FastAPI router.
    _write(
        root,
        "api.py",
        "from fastapi import APIRouter\n"
        "\n"
        "router = APIRouter()\n"
        "\n"
        "\n"
        "@router.get('/items')\n"
        "def list_items():\n"
        "    return []\n",
    )

    # A .gitignore'd file must never appear in the graph.
    _write(root, ".gitignore", "secret.py\n")
    _write(root, "secret.py", "def leaked():\n    return 1\n")

    return scan_repo(root)


def _calls_from(graph, src_id):
    return [e for e in graph.edges if e.kind == "calls" and e.src == src_id]


def test_pyyaml_is_a_known_dependency(neg_graph):
    # Sanity: the dependency exists, so a false edge would have a real target.
    assert neg_graph.get_node("dep:PyPI:PyYAML") is not None


def test_shadowed_import_param_yields_no_dep_edge(neg_graph):
    # def f(y): y.load(1) -- the param shadows ``import yaml as y``.
    assert _calls_from(neg_graph, "fn:shadow.py:f") == [], (
        "shadowed param must not produce any call edge"
    )
    node = neg_graph.get_node("fn:shadow.py:f")
    assert node is not None
    assert "y.load" in node.attrs.get("unresolved_calls", [])


def test_method_dispatch_is_unresolved(neg_graph):
    # obj.method() on a parameter, self.helper() on an instance: no edges.
    assert _calls_from(neg_graph, "fn:shadow.py:g") == []
    g_node = neg_graph.get_node("fn:shadow.py:g")
    assert "obj.method" in g_node.attrs.get("unresolved_calls", [])

    assert _calls_from(neg_graph, "fn:shadow.py:C.method") == []
    m_node = neg_graph.get_node("fn:shadow.py:C.method")
    assert "self.helper" in m_node.attrs.get("unresolved_calls", [])


def test_syntax_error_file_records_parse_error_and_scan_continues(neg_graph):
    broken = neg_graph.get_node("mod:broken")
    assert broken is not None
    assert broken.attrs.get("parse_error")
    # The rest of the scan still produced nodes from the well-formed files.
    assert neg_graph.get_node("fn:views.py:home") is not None
    assert neg_graph.get_node("dep:PyPI:PyYAML") is not None


def test_django_urlpatterns_wired_to_handler(neg_graph):
    ep = neg_graph.get_node("ep:ANY:/home/")
    assert ep is not None
    assert ep.attrs["method"] == "ANY"
    assert any(
        e.kind == "route_to_handler"
        and e.src == "ep:ANY:/home/"
        and e.dst == "fn:views.py:home"
        for e in neg_graph.edges
    ), "missing Django route_to_handler edge"


def test_fastapi_router_entrypoint_detected(neg_graph):
    ep = neg_graph.get_node("ep:GET:/items")
    assert ep is not None
    assert ep.attrs["method"] == "GET"
    assert ep.attrs.get("framework") == "fastapi"
    assert any(
        e.kind == "route_to_handler"
        and e.src == "ep:GET:/items"
        and e.dst == "fn:api.py:list_items"
        for e in neg_graph.edges
    ), "missing FastAPI route_to_handler edge"


def test_gitignored_file_absent_from_graph(neg_graph):
    assert neg_graph.get_node("file:secret.py") is None
    assert neg_graph.get_node("fn:secret.py:leaked") is None
