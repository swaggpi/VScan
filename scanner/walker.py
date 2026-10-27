"""Repository traversal and file classification.

The walker performs the first pass of a scan: it walks the target repository,
skipping version-control metadata, virtual environments, build output and
anything matched by the repository's own ``.gitignore`` (via :mod:`pathspec`),
then classifies each surviving file by language and role.

Every non-ignored file becomes a ``file`` node in the knowledge graph. Later
passes (manifests, analyzers, docs) consume the returned :class:`FileInfo`
records to decide what to do with each file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pathspec

from .graph import KnowledgeGraph

# Directories that are always skipped, regardless of .gitignore. These never
# contain first-party source worth analysing and would otherwise explode the
# graph (e.g. node_modules).
ALWAYS_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".egg-info",
    }
)

# Extension -> language. Lower-cased extensions including the leading dot.
_EXT_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".go": "go",
    ".md": "markdown",
    ".markdown": "markdown",
    ".rst": "rst",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
    ".cfg": "ini",
    ".ini": "ini",
}

# Exact filenames that are dependency manifests.
_MANIFEST_FILES: frozenset[str] = frozenset(
    {"pyproject.toml", "package.json", "composer.json", "go.mod", "Pipfile"}
)

# Exact filenames that are lockfiles.
_LOCKFILE_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "Pipfile.lock",
        "composer.lock",
        "go.sum",
    }
)


@dataclass
class FileInfo:
    """Classification of a single file in the target repository."""

    relpath: str  # path relative to repo root, using forward slashes
    abspath: str  # absolute path on disk
    language: str  # e.g. "python", or "unknown"
    role: str  # one of: source, manifest, lockfile, doc, other
    size: int  # size in bytes


def _language_for(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    return _EXT_LANGUAGE.get(ext.lower(), "unknown")


def _is_doc(relpath: str, filename: str) -> bool:
    lower = filename.lower()
    if lower.startswith("readme"):
        return True
    if lower.endswith((".md", ".markdown", ".rst")):
        return True
    # OpenAPI / Swagger specs by filename.
    stem = os.path.splitext(lower)[0]
    if stem in {"openapi", "swagger"}:
        return True
    # Anything under a top-level or nested docs/ directory.
    parts = relpath.split("/")
    if "docs" in parts[:-1]:
        return True
    return False


def _classify_role(relpath: str, filename: str, language: str) -> str:
    if filename in _MANIFEST_FILES:
        return "manifest"
    # requirements*.txt is a manifest, not plain text.
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return "manifest"
    if filename in _LOCKFILE_FILES:
        return "lockfile"
    if _is_doc(relpath, filename):
        return "doc"
    if language in {"python", "javascript", "typescript", "php", "go"}:
        return "source"
    return "other"


def _load_gitignore(repo_root: str) -> pathspec.PathSpec | None:
    gitignore = os.path.join(repo_root, ".gitignore")
    if not os.path.isfile(gitignore):
        return None
    try:
        with open(gitignore, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def walk_repo(repo_root: str, graph: KnowledgeGraph) -> list[FileInfo]:
    """Walk ``repo_root``, add a ``file`` node per file, return the file list.

    Ignored files (version control, vendored deps, build output, .gitignore
    matches) are skipped entirely and produce no nodes.
    """
    repo_root = os.path.abspath(repo_root)
    spec = _load_gitignore(repo_root)
    files: list[FileInfo] = []

    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Prune skip directories in place so os.walk does not descend into them.
        rel_dir = os.path.relpath(dirpath, repo_root)
        kept_dirs = []
        for d in dirnames:
            if d in ALWAYS_SKIP_DIRS or d.endswith(".egg-info"):
                continue
            child_rel = d if rel_dir == "." else f"{rel_dir}/{d}"
            child_rel = child_rel.replace(os.sep, "/")
            if spec is not None and spec.match_file(child_rel + "/"):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            abspath = os.path.join(dirpath, filename)
            relpath = os.path.relpath(abspath, repo_root).replace(os.sep, "/")
            if spec is not None and spec.match_file(relpath):
                continue
            if not os.path.isfile(abspath) or os.path.islink(abspath):
                continue
            try:
                size = os.path.getsize(abspath)
            except OSError:
                size = 0

            language = _language_for(filename)
            role = _classify_role(relpath, filename, language)
            info = FileInfo(
                relpath=relpath,
                abspath=abspath,
                language=language,
                role=role,
                size=size,
            )
            files.append(info)
            graph.add_node(
                f"file:{relpath}",
                "file",
                filename,
                relpath=relpath,
                language=language,
                role=role,
                size=size,
            )

    files.sort(key=lambda f: f.relpath)
    return files
