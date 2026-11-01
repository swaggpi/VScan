"""Tests for the Phase-2 INFERRED-EDGE tier + "likely" reachability view.

These never touch the network or require an API key: an in-test stub client
stands in for :class:`scanner.agent.LLMClient`, returning canned JSON so the
grounding / validation / firewall logic is exercised deterministically, while an
offline stub forces the graceful no-inference path.

The star of the file is the CARDINAL-RULE FIREWALL test: running the inference
tier must leave the proven ``compute_reachability`` output byte-identical and
must never leak an inferred edge into the real graph.
"""

from __future__ import annotations

import copy
from typing import Any

from scanner.correlate import CorrelationResult
from scanner.enrich.edges import (
    _CONFIDENCE_VALUES,
    infer_edges,
    likely_reachability,
)
from scanner.graph import KnowledgeGraph
from scanner.reachability import compute_reachability

# Node ids used across the fixtures.
EP = "ep:POST:/import"
FN_HANDLER = "fn:app.py:import_doc"  # the route handler; has an unresolved call
FN_RUN = "fn:app.py:run_import"  # deterministically calls PyYAML
DEP_YAML = "dep:PyPI:PyYAML"  # vulnerable dep, unreachable until the edge is inferred

# The unresolved call site on the handler. Its tokens ("run", "import") overlap
# FN_RUN's name tokens, so FN_RUN lands on its grounded shortlist.
UNRESOLVED_CALL = "handlers.run_import(payload)"


class _StubClient:
    """Available duck-typed client returning a canned ``complete_json`` body."""

    def __init__(self, response: dict[str, Any] | None):
        self._response = response
        self.calls = 0

    def available(self) -> bool:
        return True

    def complete_json(self, system_prompt: str, user_prompt: str):
        self.calls += 1
        return self._response


class _OfflineClient:
    """Never-available client: forces the graceful no-inference path."""

    def available(self) -> bool:
        return False

    def complete_json(self, system_prompt: str, user_prompt: str):  # pragma: no cover
        raise AssertionError("offline client must not be called")


def _mapping_response(target: str | None, confidence: str = "high") -> dict[str, Any]:
    return {
        "mappings": [
            {
                "call": UNRESOLVED_CALL,
                "target": target,
                "confidence": confidence,
                "rationale": "dispatches to the importer",
            }
        ]
    }


def _graph(*, handler_calls_run: bool = False) -> KnowledgeGraph:
    """A tiny repo: an entry point whose handler has one unresolved call, and a
    separate ``run_import`` function that deterministically calls PyYAML.

    With ``handler_calls_run`` the handler ALSO has a resolved ``calls`` edge to
    ``run_import`` (used to prove the deterministic-duplicate skip).
    """
    g = KnowledgeGraph()
    g.add_node(EP, "entrypoint", "POST /import", method="POST", path="/import")
    g.add_node(
        FN_HANDLER,
        "function",
        "import_doc",
        relpath="app.py",
        signature="import_doc(payload)",
        unresolved_calls=[UNRESOLVED_CALL],
        unresolved_call_count=1,
    )
    g.add_node(FN_RUN, "function", "run_import", relpath="app.py")
    g.add_node(DEP_YAML, "dependency", "PyYAML", ecosystem="PyPI", version="5.3")
    g.add_edge(EP, FN_HANDLER, "route_to_handler")
    g.add_edge(FN_RUN, DEP_YAML, "calls", symbol="yaml.load")
    if handler_calls_run:
        g.add_edge(FN_HANDLER, FN_RUN, "calls")
    return g


def _correlation() -> CorrelationResult:
    # Findings are only read to order the shortlist (vulnerable deps first); the
    # inference logic does not depend on them, so an empty result is fine.
    return CorrelationResult(findings=[], offline=True, network_ok=False)


def _edges_set(graph: KnowledgeGraph) -> set[tuple[str, str, str, str]]:
    return {
        (e.src, e.dst, e.kind, str(e.attrs.get("symbol", ""))) for e in graph.edges
    }


# -- the cardinal-rule firewall ----------------------------------------------


def test_firewall_proven_output_is_byte_identical_and_graph_untouched():
    graph = _graph()
    correlation = _correlation()

    # Proven reachability on the ORIGINAL graph, before any inference.
    proven = compute_reachability(graph)
    proven_dict_before = proven.to_dict()
    edges_before = _edges_set(graph)
    nodes_before = {
        n.id: (n.kind, n.name, copy.deepcopy(n.attrs)) for n in graph.nodes
    }
    # PyYAML is NOT proven-reachable (the one call site reaching it is unresolved).
    assert {d["id"] for d in proven.repo.reachable_deps} == set()

    # Run the full Phase-2 tier with a model that DOES infer the edge.
    stub = _StubClient(_mapping_response(FN_RUN))
    inferred = infer_edges(graph, proven, correlation, stub)
    assert inferred, "the stub model should have produced an inferred edge"
    likely = likely_reachability(graph, inferred, proven)

    # The inferred edge surfaces PyYAML as a LIKELY lead...
    assert any(
        entry["dependency_id"] == DEP_YAML for entry in likely["likely_reachable"]
    )

    # ...but the proven pipeline is byte-identical and the graph is untouched.
    assert compute_reachability(graph).to_dict() == proven_dict_before
    assert _edges_set(graph) == edges_before
    assert {n.id: (n.kind, n.name, n.attrs) for n in graph.nodes} == nodes_before
    # No inferred edge leaked into the real graph.
    assert (FN_HANDLER, FN_RUN, "calls", "") not in _edges_set(graph)
    # Proven reachable set is still empty (never upgraded to reachable).
    assert {d["id"] for d in compute_reachability(graph).repo.reachable_deps} == set()


# -- grounding: only real, shortlisted ids survive validation -----------------


def test_inferred_edge_references_real_shortlisted_node():
    graph = _graph()
    proven = compute_reachability(graph)
    inferred = infer_edges(graph, proven, _correlation(), _StubClient(_mapping_response(FN_RUN)))

    assert len(inferred) == 1
    edge = inferred[0]
    assert edge["src"] == FN_HANDLER
    assert edge["dst"] == FN_RUN
    assert graph.has_node(edge["dst"])
    assert edge["kind"] == "calls"
    assert edge["origin"] == "inferred"
    assert edge["confidence"] in _CONFIDENCE_VALUES
    assert edge["symbol"] == "handlers.run_import"
    # Grounding source is the CODE site: the calling file + the unresolved line.
    assert edge["sources"] == [{"file": "app.py", "snippet": UNRESOLVED_CALL}]
    assert edge["rationale"]


def test_hallucinated_target_is_rejected():
    graph = _graph()
    proven = compute_reachability(graph)
    # The model invents an id that is neither on the shortlist nor in the graph.
    stub = _StubClient(_mapping_response("fn:app.py:does_not_exist"))
    inferred = infer_edges(graph, proven, _correlation(), stub)
    assert inferred == []


def test_target_outside_shortlist_is_rejected():
    graph = _graph()
    proven = compute_reachability(graph)
    # DEP_YAML is a real node but shares no name token with the call, so it was
    # never on the shortlist for this call -> must be rejected even though real.
    stub = _StubClient(_mapping_response(DEP_YAML))
    inferred = infer_edges(graph, proven, _correlation(), stub)
    assert inferred == []


def test_null_target_declined_yields_no_edge():
    graph = _graph()
    proven = compute_reachability(graph)
    inferred = infer_edges(graph, proven, _correlation(), _StubClient(_mapping_response(None)))
    assert inferred == []


# -- no self-loops / no duplicate of an existing deterministic edge ----------


def test_self_loop_is_rejected():
    graph = _graph()
    proven = compute_reachability(graph)
    # The handler is excluded from its own shortlist, so pointing at itself is
    # rejected (and the explicit self-loop guard is a second line of defence).
    stub = _StubClient(_mapping_response(FN_HANDLER))
    inferred = infer_edges(graph, proven, _correlation(), stub)
    assert inferred == []


def test_duplicate_of_existing_deterministic_edge_is_skipped():
    # The resolved calls edge handler -> run_import already exists; inferring it
    # again adds nothing, so it is skipped.
    graph = _graph(handler_calls_run=True)
    proven = compute_reachability(graph)
    stub = _StubClient(_mapping_response(FN_RUN))
    inferred = infer_edges(graph, proven, _correlation(), stub)
    assert inferred == []


# -- likely reachability: new deps only, each via an inferred edge ------------


def test_likely_reachable_are_new_deps_reached_via_an_inferred_edge():
    graph = _graph()
    proven = compute_reachability(graph)
    proven_ids = {d["id"] for d in proven.repo.reachable_deps}

    inferred = infer_edges(graph, proven, _correlation(), _StubClient(_mapping_response(FN_RUN)))
    result = likely_reachability(graph, inferred, proven)

    likely = result["likely_reachable"]
    assert likely, "PyYAML should now be a likely-reachable lead"
    # inferred_edges echoed back verbatim.
    assert result["inferred_edges"] == inferred

    inferred_pairs = {(e["src"], e["dst"]) for e in inferred}
    for entry in likely:
        # Every likely dep is NOT already proven-reachable.
        assert entry["dependency_id"] not in proven_ids
        assert entry["confidence"] in _CONFIDENCE_VALUES
        via = entry["via"]
        # via is a concrete path entrypoint -> ... -> dep.
        assert via[0] == EP
        assert via[-1] == entry["dependency_id"]
        # ...that crosses at least one inferred edge.
        crossed = [
            (via[i], via[i + 1])
            for i in range(len(via) - 1)
            if (via[i], via[i + 1]) in inferred_pairs
        ]
        assert crossed, "likely path must traverse >=1 inferred edge"

    pyyaml = next(e for e in likely if e["dependency_id"] == DEP_YAML)
    assert pyyaml["name"] == "PyYAML"
    assert pyyaml["via"] == [EP, FN_HANDLER, FN_RUN, DEP_YAML]
    assert pyyaml["confidence"] == "high"


# -- offline client: graceful no-inference -----------------------------------


def test_offline_client_yields_no_inference_and_empty_likely():
    graph = _graph()
    proven = compute_reachability(graph)
    inferred = infer_edges(graph, proven, _correlation(), _OfflineClient())
    assert inferred == []
    result = likely_reachability(graph, inferred, proven)
    assert result["likely_reachable"] == []
    assert result["inferred_edges"] == []


def test_none_client_yields_no_inference():
    graph = _graph()
    proven = compute_reachability(graph)
    assert infer_edges(graph, proven, _correlation(), None) == []


# -- confidence is the weaker of match strength and model certainty -----------


def test_confidence_downgraded_by_weaker_model_certainty():
    graph = _graph()
    proven = compute_reachability(graph)
    # Strong token match (high), but the model is only "low" certain -> low wins.
    stub = _StubClient(_mapping_response(FN_RUN, confidence="low"))
    inferred = infer_edges(graph, proven, _correlation(), stub)
    assert len(inferred) == 1
    assert inferred[0]["confidence"] == "low"


# -- dynamic dependency dispatch grounded in the module's imports -------------

MOD_THUMB = "cli.thumb"
FN_THUMB = "fn:cli/thumb.py:make_thumbnail"
DEP_PILLOW = "dep:PyPI:Pillow"  # imported by the module; reached only via dispatch
DEP_PARAMIKO = "dep:PyPI:paramiko"  # NOT imported by the module, no token match
# A dynamic method call. Its tokens ("image","resize","size") deliberately do
# NOT overlap "Pillow" or "paramiko", so the ONLY way Pillow lands on the
# shortlist is the module-import grounding.
DYN_CALL = "image.resize(_SIZE)"


def _graph_imported_dep() -> KnowledgeGraph:
    g = KnowledgeGraph()
    g.add_node(f"mod:{MOD_THUMB}", "module", MOD_THUMB)
    g.add_node(
        FN_THUMB,
        "function",
        "make_thumbnail",
        relpath="cli/thumb.py",
        module=MOD_THUMB,
        signature="make_thumbnail(image)",
        unresolved_calls=[DYN_CALL],
        unresolved_call_count=1,
    )
    g.add_node(DEP_PILLOW, "dependency", "Pillow", ecosystem="PyPI", version="7.1.0")
    g.add_node(DEP_PARAMIKO, "dependency", "paramiko", ecosystem="PyPI", version="2.4")
    g.add_edge(f"mod:{MOD_THUMB}", DEP_PILLOW, "imports")
    return g


def test_imported_dep_dispatch_yields_inferred_edge():
    g = _graph_imported_dep()
    client = _StubClient(
        {
            "mappings": [
                {
                    "call": DYN_CALL,
                    "target": DEP_PILLOW,
                    "confidence": "high",  # model overclaims; must be capped
                    "rationale": "image.resize is a PIL.Image method",
                }
            ]
        }
    )
    edges = infer_edges(g, compute_reachability(g), _correlation(), client=client)
    assert len(edges) == 1
    e = edges[0]
    assert (e["src"], e["dst"], e["kind"]) == (FN_THUMB, DEP_PILLOW, "calls")
    assert e["origin"] == "inferred"
    # Dynamic dep-dispatch is never near-certain: capped at medium even though
    # the model said "high".
    assert e["confidence"] == "medium"
    assert e["confidence"] in _CONFIDENCE_VALUES
    # Grounding: cites BOTH the dynamic call site and the module's import.
    snippets = [s.get("snippet", "") for s in e["sources"]]
    assert any(DYN_CALL in s for s in snippets)
    assert any("imports Pillow" in s for s in snippets)


def test_non_imported_dep_is_rejected_even_if_model_proposes_it():
    g = _graph_imported_dep()
    # paramiko is neither imported by the module nor a token match, so it is not
    # on the shortlist; a model that proposes it is rejected -> no edge.
    client = _StubClient(
        {
            "mappings": [
                {
                    "call": DYN_CALL,
                    "target": DEP_PARAMIKO,
                    "confidence": "high",
                    "rationale": "hallucinated dispatch",
                }
            ]
        }
    )
    edges = infer_edges(g, compute_reachability(g), _correlation(), client=client)
    assert edges == []
