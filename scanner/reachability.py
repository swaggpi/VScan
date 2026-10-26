"""Reachability engine: which public entry point reaches which functions and deps.

This is a pure, deterministic computation over a
:class:`~scanner.graph.KnowledgeGraph`. For every ``entrypoint`` node it answers
"starting from this public route, which functions and which declared
dependencies can be reached by following edges that actually exist in the
graph?" -- and it does so without ever inferring an edge that the structural
scan did not emit.

Traversal model
---------------
Starting at an entrypoint, we follow ``route_to_handler`` edges to the handler
function(s), then ``calls`` edges transitively. A ``function`` node is reachable
when a path of such edges reaches it; a ``dependency`` node is reached when a
``calls`` edge from a reachable function lands on it (the call's
``attrs.symbol`` is the called dependency symbol). The traversal is a
breadth-first search, so it is cycle-safe (a ``visited`` set) and the recorded
evidence path to each dependency is a shortest one.

Honesty (the cardinal rule)
---------------------------
We traverse only edges present in the graph; we never turn an *unresolved* call
into an edge. Functions carry an ``unresolved_calls`` attribute recording call
sites the analyzers could not soundly resolve (method dispatch, call-through-
data, dynamic dispatch, ...). We sum those across each entrypoint's reachable
set and expose the total as ``unresolved_calls_encountered`` so a report can
state plainly that reachability here is a *lower bound*: we under-approximate
and never claim a dependency is definitely *not* reachable when unresolved calls
exist on the reachable set.

The result is JSON-serializable via :meth:`ReachabilityResult.to_dict`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any

from .graph import Edge, KnowledgeGraph

# Edge kinds that participate in reachability traversal, in the order they are
# followed from a given node (routes first, then calls).
_TRAVERSAL_KINDS: frozenset[str] = frozenset({"route_to_handler", "calls"})


@dataclass
class ReachedDependency:
    """A dependency reached from a single entry point, with evidence."""

    id: str
    name: str
    version: str | None
    ecosystem: str | None
    symbol: str | None  # the called symbol on the shortest-path edge
    symbols: list[str]  # every distinct symbol reaching this dep from the set
    example_path: list[str]  # node ids: entrypoint -> ... -> dependency


@dataclass
class EntrypointReachability:
    """What one ``entrypoint`` node can reach."""

    id: str
    method: str
    path: str
    handlers: list[str]  # handler function node ids (route_to_handler targets)
    reachable_function_count: int
    reachable_dependencies: list[ReachedDependency]
    unresolved_calls_encountered: int


@dataclass
class RepoReachability:
    """Repo-wide reachability roll-up across all entry points.

    Each list holds small dependency summaries ``{id, name, version,
    ecosystem}``, sorted for stable output.
    """

    reachable_deps: list[dict[str, Any]] = field(default_factory=list)
    unreachable_deps: list[dict[str, Any]] = field(default_factory=list)
    deps_without_call_site: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ReachabilityResult:
    """The full reachability answer for a repository."""

    entrypoints: list[EntrypointReachability] = field(default_factory=list)
    repo: RepoReachability = field(default_factory=RepoReachability)

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable representation."""
        return asdict(self)


def _dep_summary(graph: KnowledgeGraph, dep_id: str) -> dict[str, Any]:
    """Build a small ``{id, name, version, ecosystem}`` summary for a dep node."""
    node = graph.get_node(dep_id)
    if node is None:  # pragma: no cover - callers only pass known dep ids
        return {"id": dep_id, "name": dep_id, "version": None, "ecosystem": None}
    return {
        "id": node.id,
        "name": node.name,
        "version": node.attrs.get("version"),
        "ecosystem": node.attrs.get("ecosystem"),
    }


def _build_adjacency(graph: KnowledgeGraph) -> dict[str, list[Edge]]:
    """Map ``src -> [edges]`` for traversable edges, sorted for determinism."""
    adjacency: dict[str, list[Edge]] = {}
    for edge in graph.edges:
        if edge.kind not in _TRAVERSAL_KINDS:
            continue
        adjacency.setdefault(edge.src, []).append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda e: (e.dst, str(e.attrs.get("symbol", ""))))
    return adjacency


def _unresolved_count(graph: KnowledgeGraph, fn_id: str) -> int:
    """Number of unresolved calls recorded on a function node (0 if none)."""
    node = graph.get_node(fn_id)
    if node is None:
        return 0
    count = node.attrs.get("unresolved_call_count")
    if isinstance(count, int):
        return count
    unresolved = node.attrs.get("unresolved_calls")
    return len(unresolved) if isinstance(unresolved, list) else 0


def _reachability_for_entrypoint(
    graph: KnowledgeGraph, ep_id: str, adjacency: dict[str, list[Edge]]
) -> EntrypointReachability:
    """Compute reachability from a single entrypoint via BFS over existing edges."""
    ep = graph.get_node(ep_id)
    assert ep is not None

    # BFS. ``parent[node] = (predecessor, symbol_on_edge)`` records a shortest
    # path and the symbol of the edge used to discover the node. The entrypoint
    # itself has no parent.
    parent: dict[str, tuple[str | None, str | None]] = {ep_id: (None, None)}
    order: deque[str] = deque([ep_id])

    reachable_functions: set[str] = set()
    reachable_dep_ids: set[str] = set()
    handlers: list[str] = []

    while order:
        current = order.popleft()
        for edge in adjacency.get(current, []):
            dst = edge.dst
            dst_node = graph.get_node(dst)
            if dst_node is None:
                continue
            if edge.kind == "route_to_handler" and current == ep_id:
                if dst not in handlers:
                    handlers.append(dst)
            if dst in parent:
                continue  # already discovered via a shortest (or equal) path
            symbol = edge.attrs.get("symbol")
            parent[dst] = (current, symbol)
            if dst_node.kind == "dependency":
                # A dependency is a leaf for reachability; record it but do not
                # traverse out of it.
                reachable_dep_ids.add(dst)
            elif dst_node.kind == "function":
                reachable_functions.add(dst)
                order.append(dst)
            else:
                # Any other reachable node (defensive) is still traversed.
                order.append(dst)

    reachable_dependencies = [
        _reached_dependency(graph, ep_id, dep_id, parent, reachable_functions)
        for dep_id in reachable_dep_ids
    ]
    reachable_dependencies.sort(key=lambda d: (d.name, d.id))

    unresolved_total = sum(_unresolved_count(graph, fn) for fn in reachable_functions)

    return EntrypointReachability(
        id=ep_id,
        method=str(ep.attrs.get("method", "?")),
        path=str(ep.attrs.get("path", "?")),
        handlers=sorted(handlers),
        reachable_function_count=len(reachable_functions),
        reachable_dependencies=reachable_dependencies,
        unresolved_calls_encountered=unresolved_total,
    )


def _reached_dependency(
    graph: KnowledgeGraph,
    ep_id: str,
    dep_id: str,
    parent: dict[str, tuple[str | None, str | None]],
    reachable_functions: set[str],
) -> ReachedDependency:
    """Assemble the evidence record for one reached dependency."""
    # Reconstruct the shortest path entrypoint -> ... -> dep from parent links.
    path: list[str] = []
    node: str | None = dep_id
    while node is not None:
        path.append(node)
        node = parent[node][0]
    path.reverse()

    shortest_symbol = parent[dep_id][1]

    # Every distinct symbol by which a reachable function calls this dependency.
    symbols = sorted(
        {
            str(e.attrs["symbol"])
            for e in graph.edges
            if e.kind == "calls"
            and e.dst == dep_id
            and e.src in reachable_functions
            and e.attrs.get("symbol") is not None
        }
    )

    summary = _dep_summary(graph, dep_id)
    return ReachedDependency(
        id=summary["id"],
        name=summary["name"],
        version=summary["version"],
        ecosystem=summary["ecosystem"],
        symbol=shortest_symbol,
        symbols=symbols,
        example_path=path,
    )


def compute_reachability(graph: KnowledgeGraph) -> ReachabilityResult:
    """Compute per-entrypoint and repo-wide reachability for ``graph``.

    Pure and deterministic: identical graphs yield identical results. See the
    module docstring for the traversal and honesty model.
    """
    adjacency = _build_adjacency(graph)

    entrypoints = [
        _reachability_for_entrypoint(graph, ep.id, adjacency)
        for ep in sorted(graph.nodes_of_kind("entrypoint"), key=lambda n: n.id)
    ]

    # Repo-wide: deps reachable from ANY entrypoint vs. declared-but-unreached.
    reachable_any: set[str] = set()
    for ep_result in entrypoints:
        for dep in ep_result.reachable_dependencies:
            reachable_any.add(dep.id)

    declared_dep_ids = {n.id for n in graph.nodes_of_kind("dependency")}
    unreachable = declared_dep_ids - reachable_any

    # Deps with no incoming ``calls`` edge at all (declared/imported but with no
    # resolved call site anywhere -- not even module-level). A strictly stronger
    # signal than "unreachable from an entry point".
    called_dep_ids = {
        e.dst
        for e in graph.edges
        if e.kind == "calls" and e.dst in declared_dep_ids
    }
    without_call_site = declared_dep_ids - called_dep_ids

    def _summaries(ids: set[str]) -> list[dict[str, Any]]:
        out = [_dep_summary(graph, dep_id) for dep_id in ids]
        out.sort(key=lambda d: (str(d["ecosystem"]), str(d["name"])))
        return out

    repo = RepoReachability(
        reachable_deps=_summaries(reachable_any),
        unreachable_deps=_summaries(unreachable),
        deps_without_call_site=_summaries(without_call_site),
    )

    return ReachabilityResult(entrypoints=entrypoints, repo=repo)
