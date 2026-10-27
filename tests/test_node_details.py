"""Node-detail assertions for the ``samples/demo-app`` demo fixture.

These cover the extra per-node detail a UI shows on click, layered on top of the
structural scan:

* ``function`` nodes carry a ``docstring`` and a readable ``signature`` (plus the
  definition ``lineno``);
* ``entrypoint``/``function`` nodes carry a ``docs`` attr: a list of
  ``{"source", "snippet"}`` references naming which docs mention the node and the
  quoted excerpt, and the excerpt genuinely comes from the cited source file.

They are offline and deterministic (structural scan only, no CVE/OSV data).
"""

from __future__ import annotations

import os

from scanner.docs import _EXCERPT_LEN
from scanner.scan import scan_repo

_DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "demo-app",
)


def _graph():
    return scan_repo(_DEMO)


def _normalize(text: str) -> str:
    """Collapse runs of whitespace, matching how ``docs._snippet`` is built."""
    return " ".join(text.split())


# -- function detail --------------------------------------------------------


def test_function_node_has_docstring_and_signature():
    graph = _graph()

    loader = graph.get_node("fn:parsers/loader.py:load_document")
    assert loader is not None, "expected load_document function node"
    assert loader.attrs.get("signature") == "load_document(raw)"
    docstring = loader.attrs.get("docstring")
    assert isinstance(docstring, str) and docstring.strip()
    assert "yaml" in docstring.lower()
    assert isinstance(loader.attrs.get("lineno"), int)

    ingest = graph.get_node("fn:services/config_service.py:ingest")
    assert ingest is not None, "expected ingest function node"
    assert ingest.attrs.get("signature") == "ingest(raw)"
    assert (ingest.attrs.get("docstring") or "").strip()


# -- per-node doc references ------------------------------------------------


def test_entrypoint_node_carries_doc_references():
    graph = _graph()

    ep = graph.get_node("ep:POST:/configs/import")
    assert ep is not None, "expected POST /configs/import entrypoint node"

    refs = ep.attrs.get("docs")
    assert isinstance(refs, list) and refs, "entrypoint should carry doc references"

    sources = {ref["source"] for ref in refs}
    # The route is documented in both the README table and the OpenAPI spec.
    assert "README.md" in sources

    for ref in refs:
        assert set(ref) >= {"source", "snippet"}
        assert ref["snippet"].strip()
        # The quoted excerpt must genuinely appear in the cited source file
        # (comparing after the same whitespace normalisation the snippet uses).
        source_path = os.path.join(_DEMO, ref["source"])
        with open(source_path, encoding="utf-8", errors="replace") as handle:
            file_text = _normalize(handle.read())
        assert _normalize(ref["snippet"]) in file_text, (
            f"snippet for {ref['source']} not found in that source file"
        )


def test_doc_references_are_deduped():
    graph = _graph()

    for node in graph.nodes:
        refs = node.attrs.get("docs")
        if not refs:
            continue
        seen = {(r["source"], r["snippet"]) for r in refs}
        assert len(seen) == len(refs), f"duplicate doc refs on {node.id}"


# -- doc-node excerpt (repo-level context) ----------------------------------


def test_doc_node_excerpt_is_long_but_bounded():
    # The doc-node ``excerpt`` is kept generous (not a tiny ~300-char window) so
    # a repo-level fact stated a bit deeper in a doc -- e.g. the PostgreSQL /
    # SQLAlchemy persistence note in the OpenAPI spec -- is retained in the
    # node, yet it stays bounded by _EXCERPT_LEN so a huge doc never bloats the
    # graph.
    graph = _graph()

    spec = graph.get_node("doc:openapi.yaml")
    assert spec is not None, "expected openapi.yaml doc node"
    excerpt = spec.attrs.get("excerpt")
    assert isinstance(excerpt, str)
    assert len(excerpt) > 300  # retained past the old 300-char cap
    assert len(excerpt) <= _EXCERPT_LEN  # still bounded
    # The deeper repo-level fact now lives inside the node excerpt.
    assert "PostgreSQL" in excerpt and "SQLAlchemy" in excerpt
