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
    # Taint-fixture routes (see scanner/taint.py and this app's README).
    "ep:POST:/load",
    "ep:GET:/echo",
    "ep:GET:/proxy",
}

EXPECTED_ROUTES = {
    ("ep:GET:/decorated", "fn:app.py:decorated"),
    ("ep:POST:/submit", "fn:app.py:submit"),
    ("ep:GET:/fetch", "fn:app.py:fetch"),
    ("ep:GET:/added", "fn:app.py:added"),
    ("ep:GET:/api/items", "fn:app.py:list_items"),
    ("ep:POST:/load", "fn:app.py:load_config"),
    ("ep:GET:/echo", "fn:app.py:echo"),
    ("ep:GET:/proxy", "fn:app.py:proxy"),
}

EXPECTED_FN_CALLS = {
    ("fn:app.py:submit", "fn:services.py:ingest"),
    ("fn:app.py:fetch", "fn:services.py:fetch_remote"),
    ("fn:app.py:list_items", "fn:services.py:parse_dates"),
    ("fn:app.py:decorated", "fn:services.py:describe"),
    ("fn:app.py:added", "fn:services.py:describe"),
    ("fn:services.py:ingest", "fn:services.py:load_yaml"),
    # Taint-fixture cross-file chain: POST /load -> parse_config -> load_yaml.
    ("fn:app.py:load_config", "fn:services.py:parse_config"),
    ("fn:services.py:parse_config", "fn:services.py:load_yaml"),
    ("fn:app.py:proxy", "fn:services.py:fetch_remote"),
    # cross-file, module-level call made from INSIDE a method body:
    ("fn:store.py:Store.save", "fn:services.py:persist"),
    # self-method call (same file): Store.save -> self._validate(...)
    ("fn:store.py:Store.save", "fn:store.py:Store._validate"),
    # instance method on a cross-file imported class: bootstrap -> Store().save()
    ("fn:offline.py:bootstrap", "fn:store.py:Store.save"),
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
    # Flask is now reachable: the taint-fixture handlers read the Flask
    # ``request`` object (request.get_json / request.args.get), which the
    # analyzer resolves as calls into the Flask dependency.
    "dep:PyPI:Flask": REACHABLE,
    "dep:PyPI:urllib3": UNREACHABLE,
    "dep:PyPI:click": UNREACHABLE,
    "dep:PyPI:itsdangerous": UNREACHABLE,
}

# Taint ground truth (hand-verified; see this app's README). Only reached deps
# can appear; a dep is ``tainted`` iff some reaching path proves attacker input
# flows into its sink, else ``not_proven``.
EXPECTED_TAINT = {
    # POST /load: request.get_json() -> parse_config -> load_yaml -> yaml.safe_load
    "dep:PyPI:PyYAML": "tainted",
    # requests is reached only with constant URLs (/fetch, /proxy); the request
    # source read in /proxy is never forwarded to the sink.
    "dep:PyPI:requests": "not_proven",
    # python-dateutil is reached with a constant list literal (/api/items).
    "dep:PyPI:python-dateutil": "not_proven",
    # Flask is the SOURCE library, not a sink receiving attacker data.
    "dep:PyPI:Flask": "not_proven",
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


def test_symbol_match_confirmed_for_pyyaml_sink(graph, reach):
    # Ground truth (README): PyYAML is reached via ``yaml.safe_load`` on
    # POST /submit. An advisory whose text names ``safe_load`` as the vulnerable
    # function therefore pins the deterministic symbol signal to "confirmed" --
    # the vulnerable function is on a reachable call path, not just the package.
    from scanner.correlate import Finding
    from scanner.correlate import report

    finding = Finding(
        dependency_id="dep:PyPI:PyYAML",
        dependency_name="PyYAML",
        version=None,
        ecosystem="PyPI",
        vuln_id="GHSA-pyyaml-golden",
        cve_ids=["CVE-2020-1747"],
        summary="PyYAML arbitrary code execution",
        fixed_versions=["5.3.1"],
        details="The yaml.safe_load function mishandles crafted input; the sink is safe_load.",
    )
    report.join_reachability(graph, [finding], reach)

    assert finding.reachable is True
    assert "yaml.safe_load" in finding.reached_symbols
    assert finding.symbol_match == "confirmed"


# -- taint (derived, additive) ------------------------------------------------


@pytest.fixture(scope="module")
def taint(graph, reach):
    from scanner.taint import compute_taint

    return compute_taint(graph, reach, APP)


def test_taint_verdicts_exactly_match(taint):
    for dep_id, verdict in EXPECTED_TAINT.items():
        result = taint.get(dep_id)
        assert result is not None, dep_id
        assert result.verdict == verdict, dep_id


def test_tainted_pyyaml_has_full_proven_evidence(taint):
    # The tainted verdict must be backed by a proven source->sink flow along the
    # POST /load path (request body -> parse_config -> load_yaml -> safe_load).
    result = taint["dep:PyPI:PyYAML"]
    assert result.verdict == "tainted"
    assert result.source == "request.get_json"
    assert result.sink_symbol == "yaml.safe_load"
    assert result.entrypoint == "POST /load"
    assert result.path == [
        "ep:POST:/load",
        "fn:app.py:load_config",
        "fn:services.py:parse_config",
        "fn:services.py:load_yaml",
        "dep:PyPI:PyYAML",
    ]


def test_taint_never_claims_an_unreached_dep(taint):
    # A dep with no reaching path must never appear with a tainted verdict (it
    # should not appear at all; the caller defaults it to not_proven).
    for dep_id in ("dep:PyPI:urllib3", "dep:PyPI:click", "dep:PyPI:itsdangerous"):
        assert taint.get(dep_id) is None
