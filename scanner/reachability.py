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

Three-way verdict (soundness)
-----------------------------
On top of the binary reachable/unreachable split we assign every declared
dependency one of three *sound* verdicts -- the model every mature
reachability-based SCA tool uses:

* ``reachable`` -- a path of resolved ``route_to_handler``/``calls`` edges runs
  from a public entry point to the dependency. (What we have always computed.)
* ``unreachable`` -- the dependency is reached by no resolved path AND the
  entire reachable code region (every function reachable from ANY entry point)
  is *fully resolved*: not a single unresolved call sits anywhere on that
  frontier. Only under that zero-unknowns condition can we honestly claim an
  unknown edge could not possibly branch to it.
* ``potentially_reachable`` -- the dependency is reached by no resolved path,
  but at least one unresolved call exists on the reachable frontier. An edge we
  could not resolve might lead to unseen code that reaches the dependency, so we
  refuse to rule it out. This is the honest conservative answer.

The precise ``unreachable`` rule, stated once: a non-reached dependency is
``unreachable`` *if and only if* the sum of ``unresolved_call_count`` over every
function reachable from any entry point equals zero. If even one reachable
function carries an unresolved call, every non-reached dependency (including
ones with no call site at all) is ``potentially_reachable``, never
``unreachable``. The per-entry-point verdict applies the identical rule scoped
to that single entry point's reachable set.

This layer is strictly additive: ``reachable_deps``/``unreachable_deps`` keep
their original meaning (``unreachable_deps`` is still exactly declared-minus-
reachable, which the correlator reads), while the verdict is extra, richer
information exposed as ``verdict_by_dep``/``verdict_counts`` on the repo roll-up
and as a ``verdict`` field on each reached-dependency record.

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

# The three sound verdicts (see the module docstring for the exact rule).
REACHABLE: str = "reachable"
POTENTIALLY_REACHABLE: str = "potentially_reachable"
UNREACHABLE: str = "unreachable"


def _classify(reached: bool, region_fully_resolved: bool) -> str:
    """Apply the three-way rule for one (region, dependency) pair.

    ``reached`` -- a resolved path reaches the dependency in this region.
    ``region_fully_resolved`` -- the region has zero unresolved calls anywhere
    on its frontier. ``unreachable`` is only ever returned under that condition.
    """
    if reached:
        return REACHABLE
    return UNREACHABLE if region_fully_resolved else POTENTIALLY_REACHABLE


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
    # A reached dependency is, by definition, ``reachable``; the field is
    # carried explicitly so every dependency record speaks the verdict model.
    verdict: str = REACHABLE


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
    # True iff this entry point's reachable region has zero unresolved calls, so
    # an ``unreachable`` verdict for a non-reached dep is honest for this route.
    fully_resolved: bool = True
    # Per-(entry point, dependency) verdict across all declared dependencies.
    verdict_by_dep: dict[str, str] = field(default_factory=dict)


@dataclass
class RepoReachability:
    """Repo-wide reachability roll-up across all entry points.

    Each list holds small dependency summaries ``{id, name, version,
    ecosystem}``, sorted for stable output.
    """

    reachable_deps: list[dict[str, Any]] = field(default_factory=list)
    unreachable_deps: list[dict[str, Any]] = field(default_factory=list)
    deps_without_call_site: list[dict[str, Any]] = field(default_factory=list)

    # Three-way verdict layer (strictly additive; the lists above are unchanged).
    # True iff the whole reachable region across ALL entry points is fully
    # resolved -- the condition under which a non-reached dep may be
    # ``unreachable`` rather than ``potentially_reachable``.
    reachable_region_fully_resolved: bool = True
    # dep id -> "reachable" | "potentially_reachable" | "unreachable".
    verdict_by_dep: dict[str, str] = field(default_factory=dict)
    # verdict label -> number of declared deps with that verdict.
    verdict_counts: dict[str, int] = field(default_factory=dict)


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
    graph: KnowledgeGraph,
    ep_id: str,
    adjacency: dict[str, list[Edge]],
    declared_dep_ids: set[str],
) -> tuple[EntrypointReachability, set[str]]:
    """Compute reachability from a single entrypoint via BFS over existing edges.

    Returns the :class:`EntrypointReachability` plus the set of function node ids
    reachable from this entry point, so the caller can union reachable regions
    across entry points for the repo-wide verdict.
    """
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

    # Per-(entry point, dependency) verdict. "unreachable" only when THIS entry
    # point's reachable region carries no unresolved call; otherwise a non-reached
    # dependency is "potentially_reachable".
    fully_resolved = unresolved_total == 0
    reached_ids = {dep.id for dep in reachable_dependencies}
    verdict_by_dep = {
        dep_id: _classify(dep_id in reached_ids, fully_resolved)
        for dep_id in declared_dep_ids
    }

    result = EntrypointReachability(
        id=ep_id,
        method=str(ep.attrs.get("method", "?")),
        path=str(ep.attrs.get("path", "?")),
        handlers=sorted(handlers),
        reachable_function_count=len(reachable_functions),
        reachable_dependencies=reachable_dependencies,
        unresolved_calls_encountered=unresolved_total,
        fully_resolved=fully_resolved,
        verdict_by_dep=verdict_by_dep,
    )
    return result, reachable_functions


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
    declared_dep_ids = {n.id for n in graph.nodes_of_kind("dependency")}

    entrypoints: list[EntrypointReachability] = []
    reachable_region: set[str] = set()  # union of functions reachable from ANY ep
    for ep in sorted(graph.nodes_of_kind("entrypoint"), key=lambda n: n.id):
        ep_result, ep_functions = _reachability_for_entrypoint(
            graph, ep.id, adjacency, declared_dep_ids
        )
        entrypoints.append(ep_result)
        reachable_region |= ep_functions

    # Repo-wide: deps reachable from ANY entrypoint vs. declared-but-unreached.
    reachable_any: set[str] = set()
    for ep_result in entrypoints:
        for dep in ep_result.reachable_dependencies:
            reachable_any.add(dep.id)

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

    # Three-way verdict (additive). The whole reachable region is "fully
    # resolved" only when no function reachable from any entry point carries an
    # unresolved call; that is the exact condition for an honest "unreachable".
    region_fully_resolved = (
        sum(_unresolved_count(graph, fn) for fn in reachable_region) == 0
    )
    verdict_by_dep = {
        dep_id: _classify(dep_id in reachable_any, region_fully_resolved)
        for dep_id in declared_dep_ids
    }
    verdict_counts = {
        REACHABLE: 0,
        POTENTIALLY_REACHABLE: 0,
        UNREACHABLE: 0,
    }
    for verdict in verdict_by_dep.values():
        verdict_counts[verdict] += 1

    repo = RepoReachability(
        reachable_deps=_summaries(reachable_any),
        unreachable_deps=_summaries(unreachable),
        deps_without_call_site=_summaries(without_call_site),
        reachable_region_fully_resolved=region_fully_resolved,
        verdict_by_dep=verdict_by_dep,
        verdict_counts=verdict_counts,
    )

    return ReachabilityResult(entrypoints=entrypoints, repo=repo)
