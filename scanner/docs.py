"""Documentation ingestion.

Adds a ``doc`` node for each documentation file (README, Markdown/reST, anything
under a ``docs/`` directory, and OpenAPI/Swagger specs) and draws conservative
``documents`` edges from a doc to the graph nodes it references.

Matching is deliberately conservative to avoid noise: a doc links to an entry
point only when it mentions that route's exact path as a whole token, and to a
module/function only when the name appears backticked (inline code). Each edge
carries a short ``snippet`` of the surrounding text.

In addition to the ``documents`` edge, the matched reference is attached to the
*target* node as a ``docs`` attr -- a list of ``{"source": <doc relpath>,
"snippet": <excerpt>}`` -- so an entry point or function node directly carries
which docs mention it and the quoted excerpt + source file (handy for a UI that
shows node detail on click). Identical ``source``/``snippet`` pairs are deduped.
"""

from __future__ import annotations

import os
import re
from typing import Any

from .graph import KnowledgeGraph
from .walker import FileInfo

# A backticked token: `something` -- used to find explicit symbol references.
_BACKTICK = re.compile(r"`([^`]+)`")

# Per-``doc``-node ``excerpt`` cap. Kept generous (not a tiny 300-char window)
# so a repo-level fact stated a little deeper in a README/OpenAPI/docs file --
# e.g. "configs are persisted in PostgreSQL via SQLAlchemy" -- is still captured
# in the node, yet bounded so a huge doc never bloats the graph. The short,
# targeted ``documents``-edge snippets and per-node ``docs`` refs are built by
# ``_snippet`` and are unaffected by this cap.
_EXCERPT_LEN = 2500


def _is_openapi(info: FileInfo) -> bool:
    stem = os.path.splitext(os.path.basename(info.relpath))[0].lower()
    if stem in {"openapi", "swagger"}:
        return True
    if info.language in {"yaml", "json"} and info.role != "manifest":
        try:
            with open(info.abspath, encoding="utf-8", errors="replace") as handle:
                head = handle.read(2048)
        except OSError:
            return False
        return bool(re.search(r'(^|\n)\s*["\']?(openapi|swagger)["\']?\s*:', head))
    return False


def _read_text(abspath: str) -> str:
    try:
        with open(abspath, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _snippet(text: str, index: int, token: str) -> str:
    start = max(0, index - 40)
    end = min(len(text), index + len(token) + 40)
    return " ".join(text[start:end].split())


def _attach_doc_ref(
    graph: KnowledgeGraph, target_id: str, source: str, snippet: str
) -> None:
    """Record on ``target_id`` that doc ``source`` mentions it, with ``snippet``.

    Appends to the node's ``docs`` list, deduping identical ``source``/``snippet``
    pairs so a node mentioned several times (or re-scanned) stays clean. A no-op
    when the target node is absent.
    """
    node = graph.get_node(target_id)
    if node is None:
        return
    refs = node.attrs.setdefault("docs", [])
    ref = {"source": source, "snippet": snippet}
    if ref not in refs:
        refs.append(ref)


def ingest_docs(files: list[FileInfo], graph: KnowledgeGraph) -> None:
    """Add ``doc`` nodes and ``documents`` edges for documentation files."""
    # Snapshot the reference targets once.
    entrypoints = [
        (node.attrs.get("path"), node.id)
        for node in graph.nodes_of_kind("entrypoint")
        if node.attrs.get("path")
    ]
    module_names = {node.name: node.id for node in graph.nodes_of_kind("module")}
    function_names: dict[str, str] = {}
    for node in graph.nodes_of_kind("function"):
        function_names.setdefault(node.name, node.id)
    # Index a bare method/function name (last dotted segment) ONLY when it is
    # unique across the whole graph; an ambiguous bare name (e.g. two classes
    # with a ``run`` method) must not be linked to an arbitrary first match.
    bare_counts: dict[str, int] = {}
    bare_ids: dict[str, str] = {}
    for node in graph.nodes_of_kind("function"):
        bare = node.name.split(".")[-1]
        bare_counts[bare] = bare_counts.get(bare, 0) + 1
        bare_ids[bare] = node.id
    for bare, count in bare_counts.items():
        if count == 1:
            function_names.setdefault(bare, bare_ids[bare])

    for info in files:
        is_api_spec = _is_openapi(info)
        if info.role != "doc" and not is_api_spec:
            continue
        text = _read_text(info.abspath)
        doc_id = f"doc:{info.relpath}"
        graph.add_node(
            doc_id,
            "doc",
            os.path.basename(info.relpath),
            relpath=info.relpath,
            kind_hint="openapi" if is_api_spec else "prose",
            excerpt=text[:_EXCERPT_LEN].strip() or None,
        )

        _link_entrypoints(graph, doc_id, info.relpath, text, entrypoints)
        _link_symbols(
            graph, doc_id, info.relpath, text, module_names, function_names
        )


def _link_entrypoints(
    graph: KnowledgeGraph,
    doc_id: str,
    source: str,
    text: str,
    entrypoints: list[tuple[str, str]],
) -> None:
    for path, ep_id in entrypoints:
        # Match the exact path as a whole token (not a substring of a longer path).
        pattern = re.compile(r"(?<![\w/])" + re.escape(path) + r"(?![\w/])")
        match = pattern.search(text)
        if match:
            snippet = _snippet(text, match.start(), path)
            graph.add_edge(
                doc_id,
                ep_id,
                "documents",
                matched=path,
                snippet=snippet,
            )
            _attach_doc_ref(graph, ep_id, source, snippet)


def _link_symbols(
    graph: KnowledgeGraph,
    doc_id: str,
    source: str,
    text: str,
    module_names: dict[str, str],
    function_names: dict[str, str],
) -> None:
    seen: set[str] = set()
    for match in _BACKTICK.finditer(text):
        token = match.group(1).strip()
        # Strip call parentheses: `load_config()` -> load_config.
        bare = token.split("(")[0].strip()
        target_id: str | None = None
        if bare in module_names:
            target_id = module_names[bare]
        elif bare in function_names:
            target_id = function_names[bare]
        if target_id and target_id not in seen:
            seen.add(target_id)
            snippet = _snippet(text, match.start(), token)
            graph.add_edge(
                doc_id,
                target_id,
                "documents",
                matched=bare,
                snippet=snippet,
            )
            _attach_doc_ref(graph, target_id, source, snippet)
