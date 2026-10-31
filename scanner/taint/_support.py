"""Shared repo-rebuild helper for the per-language taint adapters.

Both the Go and JavaScript adapters need the analyzer's cross-file/-package
machinery rebuilt offline (the manifest ``dep:*`` nodes, the cross-file export
index and a read-once source cache). The core does not hand any of this to an
adapter, so each cache rebuilds it exactly as :func:`scanner.scan.scan_repo`
does for its first three steps. This helper is that rebuild, extracted once so
the two adapters cannot drift (they held byte-identical copies).
"""

from __future__ import annotations

from typing import Any


def _scan_support(repo_root: str) -> tuple[Any, dict[str, Any], dict[str, str]]:
    """Return ``(graph, repo_index, source_cache)`` for ``repo_root``.

    Mirrors the first three steps of :func:`scanner.scan.scan_repo` so a
    language analyzer's import/symbol resolution can be rebuilt offline: a graph
    carrying the manifest ``dep:*`` nodes, the cross-file/-package index
    (e.g. ``go_module`` / ``go_packages`` for Go) and the read-once source
    cache. The rebuilt graph is a throwaway used only to answer questions such
    as "does this package exist".
    """
    # Imported lazily to avoid any import cycle at module load.
    from ..graph import KnowledgeGraph
    from ..scan import _build_repo_index, _extract_dependencies
    from ..walker import walk_repo

    graph = KnowledgeGraph()
    files = walk_repo(repo_root, graph)
    deps = _extract_dependencies(files, graph)
    repo_index, source_cache = _build_repo_index(files, deps, graph)
    return graph, repo_index, source_cache
