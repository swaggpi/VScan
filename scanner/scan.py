"""Scan orchestration: walker -> manifests -> analyzers -> docs -> graph.

:func:`scan_repo` is the single entry point that wires the passes together and
returns a populated :class:`~scanner.graph.KnowledgeGraph`. It performs no
network I/O and reads only files inside the target repository.
"""

from __future__ import annotations

import os
from typing import Any

from . import analyzers, manifests
from .analyzers import go_analyzer, javascript_analyzer, python_analyzer
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
        deps.extend(adapter.parse(info.abspath, info.relpath))

    # Direct must win. A dep id can be emitted BOTH as a declared/direct dep and
    # again as transitive (e.g. the lockfile walk enumerates the whole tree), and
    # ``graph.add_node`` merges attrs last-write-wins. So compute, per dep id, the
    # OR of every ``direct`` flag seen FIRST; a node that is direct in any source
    # then ends up ``direct=True`` regardless of emission order, never downgraded
    # to False by a later transitive emission.
    direct_by_id: dict[str, bool] = {}
    for dep in deps:
        dep_id = dep.node_id()
        direct_by_id[dep_id] = direct_by_id.get(dep_id, False) or dep.direct

    for dep in deps:
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
            direct=direct_by_id[dep_id],
        )
        graph.add_edge(f"file:{dep.source_file}", dep_id, "declares")
    return deps


def _record_file_error(
    graph: KnowledgeGraph, relpath: str, attr: str, exc: Exception
) -> None:
    """Record a failed index/analyze pass on a file node (skip, never abort).

    A pathological source (e.g. a deeply nested/minified file that raises
    ``RecursionError``) must not take down the whole scan. The detail is stored
    under ``attr`` and mirrored to ``parse_error`` so coverage counts the file
    as failed rather than silently dropping it.
    """
    node = graph.get_node(f"file:{relpath}")
    if node is not None:
        detail = f"{type(exc).__name__}: {exc}"[:200]
        node.attrs[attr] = detail
        node.attrs["parse_error"] = detail


def _build_repo_index(
    files: list[FileInfo], deps: list[Any], graph: KnowledgeGraph
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
        "classes": {},  # relpath -> {class_qual -> {method names}}
        "import_index": python_analyzer.build_import_index(deps),
        # JavaScript cross-file index (additive; Python keys above unchanged).
        "js_files": set(),  # set of repo-relative JS paths
        "js_modules": {},  # module_relpath -> {export_name: fn_id}
        "js_esm_modules": set(),  # module_relpaths that use ESM import/export
        # Go cross-package index (additive; Python/JS keys above unchanged).
        "go_module": None,  # the single module's path from go.mod, or None
        "go_packages": {},  # local import path -> {package, exports{name: fn_id}}
        # dir relpath -> {func_name: fn_id} over ALL top-level funcs (exported
        # AND unexported) of that directory, for bare same-package cross-file
        # call/handler resolution. Ambiguous names (declared in >1 file) dropped.
        "go_package_funcs": {},
    }
    source_cache: dict[str, str] = {}

    for info in files:
        if info.language != "python":
            continue
        source = _read_source(info.abspath)
        if source is None:
            continue
        source_cache[info.relpath] = source
        module_path, quals, classes = python_analyzer.index_source(
            info.relpath, source
        )
        repo_index["modules"][module_path] = info.relpath
        repo_index["module_by_file"][info.relpath] = module_path
        repo_index["functions"][info.relpath] = quals
        repo_index["classes"][info.relpath] = classes

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
        try:
            module_relpath, exports, is_esm = javascript_analyzer.index_source(
                info.relpath, source
            )
        except Exception as exc:  # pathological source: skip, never abort scan
            _record_file_error(graph, info.relpath, "index_error", exc)
            continue
        repo_index["js_modules"][module_relpath] = exports
        if is_esm:
            repo_index["js_esm_modules"].add(module_relpath)

    # Go cross-package export index: built from Go files only, under its own
    # keys so Python/JS resolution is untouched. Requires a single go.mod so the
    # module path is unambiguous; grouped by directory, each dir resolved to its
    # import path. Done BEFORE analyzers run so a cross-package call/handler can
    # resolve into a function exported in another package of the same module.
    _build_go_index(files, repo_index, source_cache, graph)

    return repo_index, source_cache


def _read_go_module_path(abspath: str) -> str | None:
    """Return the ``module <path>`` declared by a go.mod file, or ``None``."""
    source = _read_source(abspath)
    if source is None:
        return None
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].strip('"')
    return None


def _rel_within(path: str, base: str) -> str | None:
    """POSIX-style path of ``path`` relative to ``base`` if within it, else None.

    Returns ``""`` when ``path == base``. Used to turn a Go file's directory
    into its module-relative segment; a directory outside the module root (which
    cannot belong to the module) yields ``None`` and is skipped.
    """
    rel = os.path.relpath(path or ".", base or ".")
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return None
    rel = rel.replace(os.sep, "/")
    return "" if rel == "." else rel


def _build_go_index(
    files: list[FileInfo],
    repo_index: dict[str, Any],
    source_cache: dict[str, str],
    graph: KnowledgeGraph,
) -> None:
    """Populate ``go_module`` / ``go_packages`` on ``repo_index`` (additive).

    Only a single-module repo is handled: with zero or several go.mod files the
    module path is ambiguous, so no cross-package index is built and Go stays
    single-file (sound by omission). Files are grouped by directory (one Go
    package per directory); ``_test.go`` files are excluded (not part of the
    importable package). A directory resolves only when its files agree on one
    declared package name; an exported function name that is ambiguous across
    the package's files is dropped.
    """
    go_mod_files = [f for f in files if os.path.basename(f.relpath) == "go.mod"]
    if len(go_mod_files) != 1:
        return
    go_module = _read_go_module_path(go_mod_files[0].abspath)
    if not go_module:
        return
    go_mod_dir = os.path.dirname(go_mod_files[0].relpath)

    # dir relpath -> list of (relpath, source) for the package's Go files.
    dir_files: dict[str, list[tuple[str, str]]] = {}
    for info in files:
        if info.language != "go":
            continue
        if os.path.basename(info.relpath).endswith("_test.go"):
            continue
        source = source_cache.get(info.relpath)
        if source is None:
            source = _read_source(info.abspath)
        if source is None:
            continue
        source_cache[info.relpath] = source
        dir_files.setdefault(os.path.dirname(info.relpath), []).append(
            (info.relpath, source)
        )

    go_packages: dict[str, Any] = {}
    # dir relpath -> {func_name: fn_id} over ALL top-level funcs of the dir.
    go_package_funcs: dict[str, dict[str, str]] = {}
    for directory, members in dir_files.items():
        rel = _rel_within(directory, go_mod_dir)
        import_path = None if rel is None else (
            go_module if rel == "" else f"{go_module}/{rel}"
        )
        package_names: set[str] = set()
        name_to_ids: dict[str, set[str]] = {}
        # All top-level (non-method) funcs of the directory, exported AND
        # unexported, for bare same-package cross-file resolution.
        func_name_to_ids: dict[str, set[str]] = {}
        for relpath, source in members:
            try:
                package_name, exports = go_analyzer.index_source(relpath, source)
                _pkg, all_funcs = go_analyzer.index_source_funcs(relpath, source)
            except Exception as exc:  # pathological source: skip, never abort scan
                _record_file_error(graph, relpath, "index_error", exc)
                continue
            if package_name is not None:
                package_names.add(package_name)
            for name, fn_id in exports.items():
                name_to_ids.setdefault(name, set()).add(fn_id)
            for name, fn_id in all_funcs.items():
                func_name_to_ids.setdefault(name, set()).add(fn_id)
        # Same-package bare-call map: a name declared in >1 file of the dir is
        # ambiguous (impossible in compilable Go) -> dropped, never a wrong
        # edge. Built per directory (package == directory in Go), independent
        # of module-root membership.
        go_package_funcs[directory] = {
            name: next(iter(ids))
            for name, ids in func_name_to_ids.items()
            if len(ids) == 1
        }
        # The cross-PACKAGE exported index is only meaningful within the module.
        if import_path is None:
            continue  # outside the module root
        # A directory with conflicting declared package names is left unresolved.
        package = next(iter(package_names)) if len(package_names) == 1 else None
        merged = {
            name: next(iter(ids))
            for name, ids in name_to_ids.items()
            if len(ids) == 1
        }
        go_packages[import_path] = {"package": package, "exports": merged}

    repo_index["go_module"] = go_module
    repo_index["go_packages"] = go_packages
    repo_index["go_package_funcs"] = go_package_funcs


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
    repo_index, source_cache = _build_repo_index(files, deps, graph)
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
        try:
            analyzer.analyze(file_node, source, graph, repo_index)
        except Exception as exc:  # pathological source: skip, never abort scan
            _record_file_error(graph, info.relpath, "analyze_error", exc)
            continue

    # 4. Ingest documentation (needs entry points to already exist).
    ingest_docs(files, graph)

    return graph
