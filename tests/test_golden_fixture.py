"""Golden-fixture regression: scan ``samples/golden-app`` and assert the graph
and reachability match a hand-verified answer key (see that app's README.md).

This is the one test that pins down the WHOLE pipeline against known-good data:
every route style, cross-file and dependency call resolution (incl. an aliased
import with a distribution/import name mismatch), the no-false-edge guarantees
(shadowing, rebinding, dynamic import, imported-but-not-called, and the
instance/``self`` method-call boundary), and the three-way reachability verdict
with a fully-resolved region. If the analyzer regresses -- a real edge breaks or
a false edge appears -- a specific assertion here fails.
"""

from __future__ import annotations

import os

import pytest

from scanner.reachability import (
    REACHABLE,
    UNREACHABLE,
    compute_reachability,
)
from scanner.scan import scan_repo

APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "golden-app",
)


@pytest.fixture(scope="module")
def graph():
    return scan_repo(APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


def _call_edges(graph) -> set[tuple[str, str]]:
    return {(e.src, e.dst) for e in graph.edges if e.kind == "calls"}


def _routes(graph) -> set[tuple[str, str]]:
    return {(e.src, e.dst) for e in graph.edges if e.kind == "route_to_handler"}


# -- answer key ---------------------------------------------------------------

EXPECTED_ENTRYPOINTS = {
    "ep:GET:/decorated",
    "ep:POST:/submit",
    "ep:GET:/fetch",
    "ep:GET:/added",
    "ep:GET:/api/items",
}

EXPECTED_ROUTES = {
    ("ep:GET:/decorated", "fn:app.py:decorated"),
    ("ep:POST:/submit", "fn:app.py:submit"),
    ("ep:GET:/fetch", "fn:app.py:fetch"),
    ("ep:GET:/added", "fn:app.py:added"),
    ("ep:GET:/api/items", "fn:app.py:list_items"),
}

EXPECTED_FN_CALLS = {
    ("fn:app.py:submit", "fn:services.py:ingest"),
    ("fn:app.py:fetch", "fn:services.py:fetch_remote"),
    ("fn:app.py:list_items", "fn:services.py:parse_dates"),
    ("fn:app.py:decorated", "fn:services.py:describe"),
    ("fn:app.py:added", "fn:services.py:describe"),
    ("fn:services.py:ingest", "fn:services.py:load_yaml"),
    # cross-file, module-level call made from INSIDE a method body:
    ("fn:store.py:Store.save", "fn:services.py:persist"),
}

EXPECTED_DEP_CALLS = {
    ("fn:services.py:load_yaml", "dep:PyPI:PyYAML"),
    ("fn:services.py:fetch_remote", "dep:PyPI:requests"),
    ("fn:services.py:parse_dates", "dep:PyPI:python-dateutil"),
    ("fn:offline.py:sync", "dep:PyPI:urllib3"),
}

# Edges that must NEVER be emitted (soundness: no false edges).
FORBIDDEN_CALLS = {
    ("fn:app.py:transform", "dep:PyPI:PyYAML"),   # parameter shadows the import
    ("fn:app.py:rebind", "dep:PyPI:PyYAML"),       # local rebinding shadows it
    # instance / self method-call boundary (unresolved by design):
    ("fn:offline.py:bootstrap", "fn:store.py:Store.save"),
    ("fn:store.py:Store.save", "fn:store.py:Store._validate"),
}

EXPECTED_DEP_NODES = {
    "dep:PyPI:Flask",
    "dep:PyPI:PyYAML",
    "dep:PyPI:python-dateutil",
    "dep:PyPI:requests",
    "dep:PyPI:urllib3",
    "dep:PyPI:click",
    "dep:PyPI:itsdangerous",
}

EXPECTED_VERDICTS = {
    "dep:PyPI:PyYAML": REACHABLE,
    "dep:PyPI:requests": REACHABLE,
    "dep:PyPI:python-dateutil": REACHABLE,
    "dep:PyPI:Flask": UNREACHABLE,
    "dep:PyPI:urllib3": UNREACHABLE,
    "dep:PyPI:click": UNREACHABLE,
    "dep:PyPI:itsdangerous": UNREACHABLE,
}


# -- structure ----------------------------------------------------------------


def test_entrypoints_exactly_match(graph):
    found = {n.id for n in graph.nodes if n.kind == "entrypoint"}
    assert found == EXPECTED_ENTRYPOINTS


def test_route_to_handler_edges(graph):
    assert EXPECTED_ROUTES <= _routes(graph)


def test_dependency_nodes_exactly_match(graph):
    found = {n.id for n in graph.nodes if n.kind == "dependency"}
    assert found == EXPECTED_DEP_NODES


def test_itsdangerous_is_declared_only(graph):
    # Present as a node (from the manifest) but with no import/call edge into it.
    assert graph.get_node("dep:PyPI:itsdangerous") is not None
    into = {(e.src, e.kind) for e in graph.edges if e.dst == "dep:PyPI:itsdangerous"}
    assert all(kind == "declares" for _, kind in into)


# -- call resolution (positive) -----------------------------------------------


def test_function_call_edges_resolved(graph):
    assert EXPECTED_FN_CALLS <= _call_edges(graph)


def test_dependency_call_edges_resolved(graph):
    assert EXPECTED_DEP_CALLS <= _call_edges(graph)


def test_dateutil_alias_and_name_mismatch_links_to_distribution(graph):
    # The hard one: `from dateutil import parser as dtp; dtp.parse(...)` must
    # reach the python-dateutil DISTRIBUTION despite the aliased-from import and
    # the name mismatch.
    sym = {
        e.attrs.get("symbol")
        for e in graph.edges
        if e.kind == "calls"
        and e.src == "fn:services.py:parse_dates"
        and e.dst == "dep:PyPI:python-dateutil"
    }
    assert any(s and "parse" in s for s in sym)


# -- no false edges (negative) ------------------------------------------------


def test_no_forbidden_edges(graph):
    offenders = FORBIDDEN_CALLS & _call_edges(graph)
    assert not offenders, f"analyzer fabricated edges: {sorted(offenders)}"


def test_dynamic_import_resolves_to_nothing(graph):
    # run_plugin loads a module by name: no call edge of any kind may leave it.
    out = {e.dst for e in graph.edges if e.kind == "calls" and e.src == "fn:offline.py:run_plugin"}
    assert out == set()


def test_imported_but_uncalled_dependency_has_no_call_edge(graph):
    calls_into = {e.dst for e in graph.edges if e.kind == "calls"}
    assert "dep:PyPI:click" not in calls_into


# -- reachability -------------------------------------------------------------


def test_verdicts_exactly_match(reach):
    for dep_id, verdict in EXPECTED_VERDICTS.items():
        assert reach.repo.verdict_by_dep[dep_id] == verdict, dep_id


def test_reachable_region_is_fully_resolved(reach):
    # This is what upgrades the four non-reached deps from potentially_reachable
    # to a definite unreachable -- the hardest verdict to get right soundly.
    assert reach.repo.reachable_region_fully_resolved is True


def _ep(reach, ep_id):
    for ep in reach.entrypoints:
        if ep.id == ep_id:
            return ep
    raise AssertionError(f"entrypoint {ep_id} missing")


def test_per_entrypoint_reachable_dependencies(reach):
    expected = {
        "ep:POST:/submit": {"dep:PyPI:PyYAML"},
        "ep:GET:/fetch": {"dep:PyPI:requests"},
        "ep:GET:/api/items": {"dep:PyPI:python-dateutil"},
        "ep:GET:/decorated": set(),
        "ep:GET:/added": set(),
    }
    for ep_id, deps in expected.items():
        reached = {d.id for d in _ep(reach, ep_id).reachable_dependencies}
        assert reached == deps, ep_id


def test_headline_example_path(reach):
    ep = _ep(reach, "ep:POST:/submit")
    py = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:PyYAML")
    assert py.example_path == [
        "ep:POST:/submit",
        "fn:app.py:submit",
        "fn:services.py:ingest",
        "fn:services.py:load_yaml",
        "dep:PyPI:PyYAML",
    ]
