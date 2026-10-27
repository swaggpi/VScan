"""Instance / ``self`` method-call resolution for the Python analyzer.

These build tiny throwaway repositories and assert the single-hop,
receiver-proven method dispatch resolves to the right ``ClassName.method`` node
-- and, just as importantly, that every case the analyzer cannot prove stays
unresolved (no false edge). Mirrors the boundary documented in
``samples/golden-app/README.md`` and locked by ``test_golden_fixture.py``.
"""

from __future__ import annotations

import os

import pytest

from scanner.scan import scan_repo


def _write(root: str, relpath: str, content: str) -> None:
    abspath = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(abspath) or root, exist_ok=True)
    with open(abspath, "w", encoding="utf-8") as handle:
        handle.write(content)


def _call_dsts(graph, src_id: str) -> set[str]:
    return {e.dst for e in graph.edges if e.kind == "calls" and e.src == src_id}


def _unresolved(graph, src_id: str) -> list[str]:
    node = graph.get_node(src_id)
    assert node is not None, f"missing node {src_id}"
    return node.attrs.get("unresolved_calls", [])


@pytest.fixture(scope="module")
def mc_graph(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("method_calls"))

    # A class whose methods call each other via ``self`` -- plus a ``self.X``
    # that is NOT a method of the class (must stay unresolved).
    _write(
        root,
        "store.py",
        "class Store:\n"
        "    def save(self, record):\n"
        "        self._validate(record)      # self-method -> Store._validate\n"
        "        self.missing(record)        # not a method -> unresolved\n"
        "        return record\n"
        "\n"
        "    def _validate(self, record):\n"
        "        return bool(record)\n"
        "\n"
        "    def rebinds_self(self):\n"
        "        self = Store()               # self rebound -> decline\n"
        "        return self._validate(1)\n",
    )

    # Same-file local instance.
    _write(
        root,
        "widgets.py",
        "class Widget:\n"
        "    def render(self):\n"
        "        return 1\n"
        "\n"
        "\n"
        "def build():\n"
        "    w = Widget()\n"
        "    return w.render()               # local instance -> Widget.render\n",
    )

    # Cross-file imported class: construct-and-call AND via a local var, plus the
    # negatives (reassigned var, multi-hop, external/unknown class).
    _write(
        root,
        "offline.py",
        "from store import Store\n"
        "from external_pkg import Thing\n"
        "\n"
        "\n"
        "def bootstrap():\n"
        "    return Store().save({})          # construct+call -> Store.save\n"
        "\n"
        "\n"
        "def via_var():\n"
        "    s = Store()\n"
        "    return s.save({})                # var instance -> Store.save\n"
        "\n"
        "\n"
        "def reassigned(cond):\n"
        "    s = Store()\n"
        "    if cond:\n"
        "        s = other()\n"
        "    return s.save({})                # reassigned -> unresolved\n"
        "\n"
        "\n"
        "def multihop():\n"
        "    s = Store()\n"
        "    return s.inner.save({})          # multi-hop -> unresolved\n"
        "\n"
        "\n"
        "def external():\n"
        "    return Thing().go()              # unknown class -> unresolved\n"
        "\n"
        "\n"
        "def other():\n"
        "    return object()\n",
    )

    return scan_repo(root)


# -- positives ----------------------------------------------------------------


def test_self_method_call_resolves_same_file(mc_graph):
    assert "fn:store.py:Store._validate" in _call_dsts(mc_graph, "fn:store.py:Store.save")


def test_local_instance_method_resolves_same_file(mc_graph):
    assert "fn:widgets.py:Widget.render" in _call_dsts(mc_graph, "fn:widgets.py:build")


def test_constructed_instance_method_resolves_cross_file(mc_graph):
    # Store().save(...) with ``from store import Store``.
    assert "fn:store.py:Store.save" in _call_dsts(mc_graph, "fn:offline.py:bootstrap")


def test_var_instance_method_resolves_cross_file(mc_graph):
    assert "fn:store.py:Store.save" in _call_dsts(mc_graph, "fn:offline.py:via_var")


# -- negatives (no false edge) ------------------------------------------------


def test_self_call_to_non_method_is_unresolved(mc_graph):
    # self.missing(...) -- ``missing`` is not defined on Store.
    dsts = _call_dsts(mc_graph, "fn:store.py:Store.save")
    assert "fn:store.py:Store.missing" not in dsts
    assert not any(d.endswith(":Store.missing") for d in dsts)
    assert "self.missing" in _unresolved(mc_graph, "fn:store.py:Store.save")


def test_rebound_self_declines_resolution(mc_graph):
    # self is reassigned in the body, so self._validate must not resolve.
    assert _call_dsts(mc_graph, "fn:store.py:Store.rebinds_self") == set()
    assert "self._validate" in _unresolved(mc_graph, "fn:store.py:Store.rebinds_self")


def test_reassigned_instance_var_is_unresolved(mc_graph):
    # s is assigned both Store() and other(): ambiguous -> no edge to save.
    dsts = _call_dsts(mc_graph, "fn:offline.py:reassigned")
    assert "fn:store.py:Store.save" not in dsts
    assert "s.save" in _unresolved(mc_graph, "fn:offline.py:reassigned")


def test_multihop_attribute_dispatch_is_unresolved(mc_graph):
    dsts = _call_dsts(mc_graph, "fn:offline.py:multihop")
    assert "fn:store.py:Store.save" not in dsts
    assert "s.inner.save" in _unresolved(mc_graph, "fn:offline.py:multihop")


def test_method_call_on_unknown_class_is_unresolved(mc_graph):
    # Thing is imported from a package that is not part of the repo.
    assert _call_dsts(mc_graph, "fn:offline.py:external") == set()
    assert "Thing().go" in _unresolved(mc_graph, "fn:offline.py:external")
