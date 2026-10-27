"""Shared tree-sitter node helpers common to the JS/TS, Go and PHP analyzers.

These are generic tree-sitter node operations (``prev_sibling`` walks,
``start_point`` comparisons, ``child_by_field_name("parameters")``) with no
language-specific content. The language-specific comment-marker stripping lives
in each analyzer's own ``_clean_comment`` -- ``_leading_doc_comment`` takes that
cleaner as an argument so the shared walk stays language-agnostic.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Longest docstring stored on a node (keeps the graph JSON compact).
_DOCSTRING_LIMIT = 500


def _leading_doc_comment(
    fnode: Any, clean: Callable[[str], str | None]
) -> str | None:
    """Best-effort docstring: the comment block directly above a declaration.

    Walks consecutive comment siblings immediately preceding ``fnode`` (no blank
    line between them and the declaration). Returns ``None`` when there is no
    adjacent comment -- it never reaches for an unrelated comment elsewhere.

    ``clean`` is the caller's language-specific comment-marker stripper (each
    analyzer's ``_clean_comment``); it is applied to the joined comment block.
    """
    lines: list[str] = []
    node = fnode.prev_sibling
    expected_row = fnode.start_point[0]
    while node is not None and node.type == "comment":
        if expected_row - node.end_point[0] > 1:
            break
        lines.append(node.text.decode("utf-8", "replace"))
        expected_row = node.start_point[0]
        node = node.prev_sibling
    if not lines:
        return None
    lines.reverse()
    return clean("\n".join(lines))


def _node_signature(qual: str, fnode: Any) -> str | None:
    """Best-effort ``name(params)`` signature from a tree-sitter declaration."""
    params = fnode.child_by_field_name("parameters")
    if params is None:
        return None
    name = qual.split(".")[-1]
    param_text = " ".join(params.text.decode("utf-8", "replace").split())
    sig = f"{name}{param_text}"
    if len(sig) > _DOCSTRING_LIMIT:
        return None
    return sig
