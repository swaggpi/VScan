"""Coverage / confidence report: how much of the code the analysis resolved.

The scanner is deliberately honest that reachability is a *lower bound* -- it
traverses only edges it could resolve and never invents one. This module turns
that honesty into concrete numbers: a quantitative summary of how much of the
target the structural scan and reachability engine actually pinned down.

:func:`compute_coverage` is a pure aggregation over an already-built
:class:`~scanner.graph.KnowledgeGraph` and an optional
:class:`~scanner.reachability.ReachabilityResult`. It performs no I/O, never
re-parses source, and never touches the network -- it only reads attributes the
analyzers and reachability engine already recorded. It is deliberately
language-agnostic and robust to missing attributes, so a node that lacks a
``language`` or ``unresolved_call_count`` simply does not contribute rather than
raising.

The resulting :class:`CoverageReport` is JSON-serializable via
:meth:`CoverageReport.to_dict`, so the CLI can embed it in the ``audit``
payload/bundle and a dashboard can render it later.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from .graph import KnowledgeGraph

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle risk
    from .reachability import ReachabilityResult

# Label used when a node carries no (or a null) ``language`` attribute.
_UNKNOWN_LANGUAGE = "unknown"


@dataclass
class FileCoverage:
    """How many files were seen and how many parsed cleanly."""

    total: int = 0
    by_language: dict[str, int] = field(default_factory=dict)
    parsed: int = 0
    parse_errors: int = 0
    # parsed / total, in [0, 1]; 1.0 when there are no files (nothing failed).
    parse_success_rate: float = 1.0


@dataclass
class FunctionCoverage:
    """How many functions were discovered, broken down by language."""

    total: int = 0
    by_language: dict[str, int] = field(default_factory=dict)


@dataclass
class CallSiteCoverage:
    """Resolved call edges vs. call sites the analyzers could not resolve.

    The two counts are NOT in the same unit, so ``resolution_rate`` is a
    conservative approximation, not an exact ratio of call sites:

    * ``resolved`` is the number of *distinct* resolved ``calls`` edges. The
      graph de-duplicates edges on ``(src, dst, kind, symbol)``, so several
      call sites to the same target collapse into one edge.
    * ``unresolved`` is the sum of the raw per-node ``unresolved_call_count``
      (every unresolved call site, not de-duplicated).

    Because ``resolved`` can undercount relative to ``unresolved``, the rate
    is a lower bound on the true share of call sites that were resolved.
    """

    resolved: int = 0
    unresolved: int = 0
    # resolved / (resolved + unresolved), in [0, 1]; 1.0 when both are zero
    # (nothing was left unresolved). A conservative lower bound -- see above.
    resolution_rate: float = 1.0


@dataclass
class EntrypointCoverage:
    """How many public entry points were found and how fully they resolved."""

    total: int = 0
    by_framework: dict[str, int] = field(default_factory=dict)
    # Routes detected but not fully resolvable (e.g. a non-literal path).
    unresolved_routes: int = 0
    # Entry points not soundly wired to a traversable handler. Taken from
    # reachability when available (its broader, authoritative definition);
    # otherwise approximated from the ``unresolved_handler`` attribute.
    without_handler: int = 0


@dataclass
class DependencyCoverage:
    """How many declared dependencies have a resolved call site, plus verdicts."""

    total: int = 0
    with_call_site: int = 0
    without_call_site: int = 0
    # Three-way reachability verdict breakdown, present only when a
    # reachability result is supplied; otherwise ``None``.
    verdict_breakdown: dict[str, int] | None = None


@dataclass
class CoverageReport:
    """A quantitative coverage/confidence summary for one scanned repository."""

    files: FileCoverage = field(default_factory=FileCoverage)
    functions: FunctionCoverage = field(default_factory=FunctionCoverage)
    call_sites: CallSiteCoverage = field(default_factory=CallSiteCoverage)
    entrypoints: EntrypointCoverage = field(default_factory=EntrypointCoverage)
    dependencies: DependencyCoverage = field(default_factory=DependencyCoverage)
    # A short, honest statement of why reachability is a lower bound here.
    confidence_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable representation."""
        return asdict(self)


def _language_of(attrs: dict[str, Any]) -> str:
    """Return a node's language label, defaulting to ``unknown``."""
    language = attrs.get("language")
    return language if isinstance(language, str) and language else _UNKNOWN_LANGUAGE


def _language_by_relpath(graph: KnowledgeGraph) -> dict[str, str]:
    """Map each file's relpath to its language (for nodes lacking one)."""
    index: dict[str, str] = {}
    for node in graph.nodes_of_kind("file"):
        relpath = node.attrs.get("relpath")
        if isinstance(relpath, str):
            index[relpath] = _language_of(node.attrs)
    return index


def _unresolved_count(attrs: dict[str, Any]) -> int:
    """Unresolved call sites recorded on a node (0 if none).

    Mirrors the reachability engine: prefer the integer ``unresolved_call_count``,
    else fall back to the length of the ``unresolved_calls`` list.
    """
    count = attrs.get("unresolved_call_count")
    if isinstance(count, int):
        return count
    unresolved = attrs.get("unresolved_calls")
    return len(unresolved) if isinstance(unresolved, list) else 0


def _unresolved_route_count(attrs: dict[str, Any]) -> int:
    """Number of detected-but-unresolved routes recorded on a node (0 if none)."""
    routes = attrs.get("unresolved_routes")
    return len(routes) if isinstance(routes, list) else 0


def _tally(items: Any) -> dict[str, int]:
    """Count occurrences of each label, returned sorted for stable output."""
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return dict(sorted(counts.items()))


def _file_coverage(graph: KnowledgeGraph) -> FileCoverage:
    files = graph.nodes_of_kind("file")
    total = len(files)

    # A parse failure is recorded either on the file node (e.g. Go) or on the
    # module node that maps to the file (e.g. Python). Collect the failing
    # relpaths from both so each counts once, then map back to files.
    failed_relpaths: set[str] = set()
    for node in (*files, *graph.nodes_of_kind("module")):
        if node.attrs.get("parse_error"):
            relpath = node.attrs.get("relpath")
            if isinstance(relpath, str):
                failed_relpaths.add(relpath)

    # Each failing relpath counts once; clamp to the file total so the rate
    # stays in [0, 1] even if a module-only failure has no matching file node.
    parse_errors = min(len(failed_relpaths), total) if total else len(failed_relpaths)
    # Never negative: with no file nodes (total == 0) a module-only failure
    # would otherwise yield ``0 - n``.
    parsed = max(0, total - parse_errors)
    return FileCoverage(
        total=total,
        by_language=_tally(_language_of(n.attrs) for n in files),
        parsed=parsed,
        parse_errors=parse_errors,
        parse_success_rate=(parsed / total) if total else 1.0,
    )


def _function_coverage(graph: KnowledgeGraph) -> FunctionCoverage:
    functions = graph.nodes_of_kind("function")
    file_lang = _language_by_relpath(graph)

    def language(attrs: dict[str, Any]) -> str:
        # Function nodes rarely carry a ``language``; fall back to the language
        # of the file that declares them (via relpath) before giving up.
        direct = attrs.get("language")
        if isinstance(direct, str) and direct:
            return direct
        relpath = attrs.get("relpath")
        if isinstance(relpath, str) and relpath in file_lang:
            return file_lang[relpath]
        return _UNKNOWN_LANGUAGE

    return FunctionCoverage(
        total=len(functions),
        by_language=_tally(language(n.attrs) for n in functions),
    )


def _call_site_coverage(graph: KnowledgeGraph) -> CallSiteCoverage:
    # ``resolved`` counts distinct (de-duplicated) calls edges while
    # ``unresolved`` sums raw call sites, so the rate is a conservative lower
    # bound rather than an exact ratio (see CallSiteCoverage).
    resolved = sum(1 for e in graph.edges if e.kind == "calls")
    unresolved = sum(
        _unresolved_count(n.attrs)
        for n in (*graph.nodes_of_kind("function"), *graph.nodes_of_kind("module"))
    )
    denom = resolved + unresolved
    return CallSiteCoverage(
        resolved=resolved,
        unresolved=unresolved,
        resolution_rate=(resolved / denom) if denom else 1.0,
    )


def _entrypoint_coverage(
    graph: KnowledgeGraph, reachability: "ReachabilityResult | None"
) -> EntrypointCoverage:
    entrypoints = graph.nodes_of_kind("entrypoint")
    unresolved_routes = sum(_unresolved_route_count(n.attrs) for n in graph.nodes)
    if reachability is not None:
        without_handler = reachability.repo.entrypoints_without_handler
    else:
        without_handler = sum(
            1 for n in entrypoints if n.attrs.get("unresolved_handler")
        )

    def framework(attrs: dict[str, Any]) -> str:
        value = attrs.get("framework")
        return value if isinstance(value, str) and value else _UNKNOWN_LANGUAGE

    return EntrypointCoverage(
        total=len(entrypoints),
        by_framework=_tally(framework(n.attrs) for n in entrypoints),
        unresolved_routes=unresolved_routes,
        without_handler=without_handler,
    )


def _dependency_coverage(
    graph: KnowledgeGraph, reachability: "ReachabilityResult | None"
) -> DependencyCoverage:
    declared = {n.id for n in graph.nodes_of_kind("dependency")}
    called = {
        e.dst for e in graph.edges if e.kind == "calls" and e.dst in declared
    }
    with_call_site = len(declared & called)
    verdict_breakdown: dict[str, int] | None = None
    if reachability is not None:
        counts = reachability.repo.verdict_counts
        verdict_breakdown = {
            "reachable": counts.get("reachable", 0),
            "potentially_reachable": counts.get("potentially_reachable", 0),
            "unreachable": counts.get("unreachable", 0),
        }
    return DependencyCoverage(
        total=len(declared),
        with_call_site=with_call_site,
        without_call_site=len(declared) - with_call_site,
        verdict_breakdown=verdict_breakdown,
    )


def _confidence_note(
    files: FileCoverage,
    call_sites: CallSiteCoverage,
    entrypoints: EntrypointCoverage,
) -> str:
    """Compose a short, honest statement of the analysis's limits.

    Always states that reachability is a lower bound, then names the concrete
    counts that make it so. With no entry points, states that reachability
    coverage is effectively nil -- nothing is provably unreachable.
    """
    base = (
        "Reachability is a lower bound: the scan traverses only resolved edges "
        "and never infers one, so a dependency marked not-reachable may still be "
        "reached via code the analysis could not resolve."
    )

    caveats: list[str] = []
    if call_sites.unresolved:
        caveats.append(f"{call_sites.unresolved} unresolved call site(s)")
    if entrypoints.unresolved_routes:
        caveats.append(f"{entrypoints.unresolved_routes} unresolved route(s)")
    if entrypoints.without_handler:
        caveats.append(
            f"{entrypoints.without_handler} entry point(s) without a resolved handler"
        )
    if files.parse_errors:
        caveats.append(f"{files.parse_errors} file(s) that failed to parse")

    sentences = [base]
    if entrypoints.total == 0:
        sentences.append(
            "No public entry points were detected, so reachability coverage is "
            "effectively nil -- without a front door nothing can be proven "
            "unreachable, and every dependency is at most potentially reachable."
        )
    if caveats:
        sentences.append("Unresolved here: " + "; ".join(caveats) + ".")
    elif entrypoints.total > 0:
        sentences.append(
            "Here the reachable region is fully resolved (no unresolved call "
            "sites, routes, handlers, or parse failures), so non-reached "
            "dependencies can be reported as unreachable with confidence."
        )
    return " ".join(sentences)


def compute_coverage(
    graph: KnowledgeGraph, reachability: "ReachabilityResult | None" = None
) -> CoverageReport:
    """Aggregate a coverage/confidence report from an existing scan.

    Pure and deterministic: it reads only attributes already present on the
    graph (and reachability, when supplied) and never re-parses or performs any
    I/O. Robust to missing attributes -- absent facts simply do not contribute.

    When ``reachability`` is given, the dependency section includes the
    three-way verdict breakdown and the entry-point ``without_handler`` count
    uses reachability's authoritative definition.
    """
    files = _file_coverage(graph)
    call_sites = _call_site_coverage(graph)
    entrypoints = _entrypoint_coverage(graph, reachability)
    return CoverageReport(
        files=files,
        functions=_function_coverage(graph),
        call_sites=call_sites,
        entrypoints=entrypoints,
        dependencies=_dependency_coverage(graph, reachability),
        confidence_note=_confidence_note(files, call_sites, entrypoints),
    )
