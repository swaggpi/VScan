"""Process-level caching and repo-path resolution for the MCP tools.

Scanning a repository builds the knowledge graph once; every tool then reuses
it. The caches are keyed by the *absolute* repo path so two spellings of the
same directory share one graph:

* ``_GRAPH_CACHE``  -- abspath -> KnowledgeGraph (the expensive, file-reading pass)
* ``_REACH_CACHE``  -- abspath -> ReachabilityResult (cheap; memoized per graph)
* ``_CORR_CACHE``   -- (abspath, offline, use_nvd) -> CorrelationResult
  (the only network-touching layer, so it is cached separately per mode)

``refresh=True`` on any accessor re-scans the repo and busts every derived
cache entry for that repo (reachability + all correlation modes), because they
are all computed from the graph.

:class:`ToolError` carries an already-actionable message; tools catch it and
return ``"Error: <message>"`` rather than leaking a traceback.
"""

from __future__ import annotations

import os

from scanner.agent import LLMClient
from scanner.correlate import CorrelationResult, correlate_full
from scanner.graph import KnowledgeGraph
from scanner.reachability import ReachabilityResult, compute_reachability
from scanner.scan import scan_repo

_GRAPH_CACHE: dict[str, KnowledgeGraph] = {}
_REACH_CACHE: dict[str, ReachabilityResult] = {}
_CORR_CACHE: dict[tuple[str, bool, bool], CorrelationResult] = {}


class ToolError(Exception):
    """Raised with a user-facing, actionable message (no traceback needed)."""


def resolve_repo(repo_path: str) -> str:
    """Validate ``repo_path`` and return its absolute, user-expanded form."""
    if not repo_path or not repo_path.strip():
        raise ToolError("repo_path is required (e.g. '.' or '/path/to/repo').")
    abspath = os.path.abspath(os.path.expanduser(repo_path))
    if not os.path.exists(abspath):
        raise ToolError(
            f"repo path does not exist: {repo_path!r} "
            f"(resolved to {abspath}). Pass a path to a local source checkout."
        )
    if not os.path.isdir(abspath):
        raise ToolError(
            f"repo path is not a directory: {repo_path!r}. "
            "Pass the repository root, not a single file."
        )
    return abspath


def _bust_derived(key: str) -> None:
    _REACH_CACHE.pop(key, None)
    for ckey in [k for k in _CORR_CACHE if k[0] == key]:
        _CORR_CACHE.pop(ckey, None)


def forget(key: str) -> None:
    """Drop the graph AND every derived cache entry for one repo abspath.

    Mirrors :func:`_bust_derived` but also evicts the graph itself, so a
    throwaway scratch tree (e.g. verify_fix's upgraded copy) leaves nothing
    behind in the process caches once it is removed. ``key`` is the absolute
    path used as the cache key (``resolve_repo``/``os.path.abspath`` form).
    """
    _GRAPH_CACHE.pop(key, None)
    _bust_derived(key)


def get_graph(repo_path: str, *, refresh: bool = False) -> tuple[str, KnowledgeGraph]:
    """Scan ``repo_path`` once and reuse; ``refresh=True`` forces a re-scan.

    Returns ``(abspath_key, graph)`` so callers can key further caches.
    """
    key = resolve_repo(repo_path)
    if refresh:
        _GRAPH_CACHE.pop(key, None)
        _bust_derived(key)
    if key not in _GRAPH_CACHE:
        _GRAPH_CACHE[key] = scan_repo(key)
    return key, _GRAPH_CACHE[key]


def get_reachability(
    repo_path: str, *, refresh: bool = False
) -> tuple[KnowledgeGraph, ReachabilityResult]:
    """Return ``(graph, reachability)``; reachability is memoized per graph."""
    key, graph = get_graph(repo_path, refresh=refresh)
    if key not in _REACH_CACHE:
        _REACH_CACHE[key] = compute_reachability(graph)
    return graph, _REACH_CACHE[key]


def get_correlation(
    repo_path: str,
    *,
    offline: bool,
    use_nvd: bool = False,
    refresh: bool = False,
) -> tuple[KnowledgeGraph, CorrelationResult]:
    """Return ``(graph, correlation)``; cached per (repo, offline, use_nvd).

    Correlation hits the network (unless ``offline``), so results are cached and
    only recomputed when ``refresh=True`` or the mode differs.
    """
    key, graph = get_graph(repo_path, refresh=refresh)
    ckey = (key, bool(offline), bool(use_nvd))
    if refresh:
        _CORR_CACHE.pop(ckey, None)
    if ckey not in _CORR_CACHE:
        _CORR_CACHE[ckey] = correlate_full(graph, offline=offline, use_nvd=use_nvd)
    return graph, _CORR_CACHE[ckey]


def build_client(offline: bool) -> LLMClient:
    """Build the advisory LLM client exactly as the CLI's audit path does.

    ``offline=True`` forces the deterministic heuristic (no network, no model).
    Otherwise a model is used *iff* ``LLM_BASE_URL`` / ``LLM_API_KEY`` /
    ``LLM_MODEL`` are configured; with no key the client is simply unavailable
    and every agent tier falls back to its offline heuristic -- so the tools
    work with no API key, just like ``vscan audit``.
    """
    return LLMClient.disabled() if offline else LLMClient()


def clear_caches() -> None:
    """Drop all cached state (used by tests for isolation)."""
    _GRAPH_CACHE.clear()
    _REACH_CACHE.clear()
    _CORR_CACHE.clear()
