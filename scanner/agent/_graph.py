"""Shared, tier-agnostic graph reads for the advisory agent tiers.

These are pure, read-only helpers over the knowledge graph and reachability
result. They carry no tier logic, so the ``calls edge -> dst dep ->
attrs['symbol']`` contract (and the reachable-dep set) lives in ONE place and is
consumed identically by the exposure/assess, exploitability/triage and
dynamic-usage tiers. Moving them here keeps a single edit site if that schema
ever changes.
"""

from __future__ import annotations

from ..graph import KnowledgeGraph
from ..reachability import ReachabilityResult


def _reachable_dep_ids(reachability: ReachabilityResult) -> set[str]:
    """Dependency ids reachable from any public entry point."""
    return {dep["id"] for dep in reachability.repo.reachable_deps}


def _called_symbols(graph: KnowledgeGraph, dep_id: str) -> list[str]:
    """The distinct dependency symbols the project calls (sorted, deduped).

    Collected from every ``calls`` edge whose ``dst`` is this ``dep:`` node; each
    such edge carries the called dependency symbol in ``attrs['symbol']`` (e.g.
    ``yaml.load``, ``flask.jsonify``). This is the project's actual usage surface
    of the dependency -- the left-hand side of the triage comparison. A
    dependency with an EMPTY result is the "no static resolving" case the
    dynamic-usage tier investigates.
    """
    symbols: set[str] = set()
    for edge in graph.edges:
        if edge.kind != "calls" or edge.dst != dep_id:
            continue
        symbol = edge.attrs.get("symbol")
        if isinstance(symbol, str) and symbol:
            symbols.add(symbol)
    return sorted(symbols)
