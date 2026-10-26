"""Scan orchestration: walker -> manifests -> analyzers -> docs -> graph.

:func:`scan_repo` is the single entry point that wires the passes together and
returns a populated :class:`~scanner.graph.KnowledgeGraph`. It performs no
network I/O and reads only files inside the target repository.
"""

from __future__ import annotations

import os
from typing import Any

from . import analyzers, manifests
from .analyzers import javascript_analyzer, python_analyzer
from .docs import ingest_docs
from .graph import KnowledgeGraph
from .walker import FileInfo, walk_repo


def _read_source(abspath: str) -> str | None:
    try:
        with open(abspath, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _extract_dependencies(files: list[FileInfo], graph: KnowledgeGraph) -> list[Any]:
    """Run manifest adapters over manifest files, adding dependency nodes."""
    deps: list[Any] = []
    for info in files:
        if info.role not in {"manifest", "lockfile"}:
            continue
        adapter = manifests.adapter_for(info.relpath)
        if adapter is None:
            continue
        for dep in adapter.parse(info.abspath, info.relpath):
            dep_id = dep.node_id()
            graph.add_node(
                dep_id,
                "dependency",
                dep.name,
                ecosystem=dep.ecosystem,
                version=dep.version,
                declared=dep.declared,
                resolved=dep.resolved,
                source_file=dep.source_file,
            )
            graph.add_edge(f"file:{dep.source_file}", dep_id, "declares")
            deps.append(dep)
    return deps


def _build_repo_index(
    files: list[FileInfo], deps: list[Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Build the cross-file index analyzers need, plus a relpath->source cache.

    The index holds the module map, per-file function sets, and the import-name
    -> dependency map, so a call in one file can resolve into a function or
    dependency declared elsewhere.
    """
    repo_index: dict[str, Any] = {
        "modules": {},  # module path -> relpath
        "module_by_file": {},  # relpath -> module path
        "functions": {},  # relpath -> {qualnames}
        "import_index": python_analyzer.build_import_index(deps),
        # JavaScript cross-file index (additive; Python keys above unchanged).
        "js_files": set(),  # set of repo-relative JS paths
        "js_modules": {},  # module_relpath -> {export_name: fn_id}
    }
    source_cache: dict[str, str] = {}

    for info in files:
        if info.language != "python":
            continue
        source = _read_source(info.abspath)
        if source is None:
            continue
        source_cache[info.relpath] = source
        module_path, quals = python_analyzer.index_source(info.relpath, source)
        repo_index["modules"][module_path] = info.relpath
        repo_index["module_by_file"][info.relpath] = module_path
        repo_index["functions"][info.relpath] = quals

    # JavaScript export index: built from JS files only, stored under its own
    # keys so Python resolution is untouched. Done BEFORE analyzers run so a
    # cross-file call/handler can resolve into a function exported elsewhere.
    for info in files:
        if info.language != "javascript":
            continue
        source = source_cache.get(info.relpath)
        if source is None:
            source = _read_source(info.abspath)
        if source is None:
            continue
        source_cache[info.relpath] = source
        repo_index["js_files"].add(info.relpath)
        module_relpath, exports = javascript_analyzer.index_source(info.relpath, source)
        repo_index["js_modules"][module_relpath] = exports

    return repo_index, source_cache


def scan_repo(repo_path: str) -> KnowledgeGraph:
    """Scan ``repo_path`` and return its knowledge graph."""
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        raise NotADirectoryError(f"not a directory: {repo_path}")

    graph = KnowledgeGraph()

    # 1. Walk the repo and emit file nodes.
    files = walk_repo(repo_path, graph)

    # 2. Extract dependencies from manifests/lockfiles.
    deps = _extract_dependencies(files, graph)

    # 3. Build the cross-file index, then run code analyzers.
    repo_index, source_cache = _build_repo_index(files, deps)
    for info in files:
        analyzer = analyzers.analyzer_for(info.language)
        if analyzer is None:
            continue  # languages without an analyzer degrade gracefully
        source = source_cache.get(info.relpath)
        if source is None:
            source = _read_source(info.abspath)
        if source is None:
            continue
        file_node = graph.get_node(f"file:{info.relpath}")
        if file_node is None:
            continue
        analyzer.analyze(file_node, source, graph, repo_index)

    # 4. Ingest documentation (needs entry points to already exist).
    ingest_docs(files, graph)

    return graph
