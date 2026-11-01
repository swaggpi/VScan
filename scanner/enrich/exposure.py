"""Per-entry-point EXPOSURE overlay (Phase 1): docs -> is this route public?

This module promotes the agent layer's advisory exposure judgement
(:func:`scanner.agent.assess_findings`) into an overlay keyed by *public entry
point* node id. The agent layer already decides, for each reachable vulnerable
dependency, how exposed it is (internet-facing vs. internal, authenticated vs.
not) from the repo's documentation; today that judgement is thrown away. Here we
collapse it to ONE exposure verdict per entry point so a UI can render "the docs
say ``POST /documents/import`` is public" directly on the node.

Framework-free, like :mod:`scanner.web.explain`: no web import, pure functions
over the already-computed graph / reachability / correlation, so it unit-tests
without the server runtime.

Hard guardrails (the cardinal rule)
-----------------------------------
This overlay is ADVISORY and ADDITIVE. It:

* takes read-only inputs and NEVER mutates a graph node/edge or a finding -- it
  only reads them (``edges`` / ``get_node`` / ``nodes_of_kind`` and the
  dataclass fields) and returns a brand-new dict;
* never produces or changes a ``reachable`` / ``confirmed`` / ``tainted`` flag
  or any verdict -- it reads reachability, it does not recompute it;
* in Phase 1 does NOT write exposure back into the graph (no edge/attr added);
* stays grounded: ``sources`` are real documentation excerpts linked to the
  entry point (never fabricated), and an exposure claim with no cited doc is
  labelled ``origin="inferred"`` with reduced confidence and says so.

With no model configured (:meth:`LLMClient.available` false) or on any client
error, :func:`scanner.agent.assess_findings` already falls back to its
deterministic offline heuristic, so the overlay still returns grounded data with
no API key.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..agent.assess import _context_source, _doc_evidence, assess_findings

if TYPE_CHECKING:  # avoid hard import cycles / heavy deps at import time
    from ..agent import Assessment, LLMClient
    from ..correlate import CorrelationResult
    from ..graph import KnowledgeGraph, Node
    from ..reachability import ReachabilityResult

# Allowed overlay vocabularies (mirror the agent layer's exposure/auth enums).
_EXPOSURE_VALUES = frozenset({"internet-facing", "internal", "unknown"})
_AUTH_VALUES = frozenset({"required", "none", "unknown"})
_ORIGIN_VALUES = frozenset({"doc", "inferred"})
_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})

# Aggregation precedence when one entry point reaches several findings: the most
# *exposed* / least-gated definite signal wins (a conservative security read),
# and any definite signal beats ``unknown``.
_EXPOSURE_RANK = {"internet-facing": 2, "internal": 1, "unknown": 0}
_AUTH_RANK = {"none": 2, "required": 1, "unknown": 0}

# Appended to the rationale when a definite exposure/auth claim has no cited doc
# evidence for THIS entry point, so an inferred judgement never masquerades as
# documentation-grounded (grounding requirement).
_INFERRED_CLAUSE = (
    " No supporting documentation was cited for this entry point, so this is an "
    "inferred (not documentation-grounded) judgement."
)


def _entrypoint_label(node: "Node") -> str:
    """Human label for an entry point node, e.g. ``"POST /documents/import"``.

    Prefers the node's ``method`` / ``path`` attrs (what reachability also uses
    to build its labels); falls back to parsing the ``ep:<METHOD>:<path>`` id so
    a label is always produced, never fabricated.
    """
    method = node.attrs.get("method")
    path = node.attrs.get("path")
    if isinstance(method, str) and method and isinstance(path, str) and path:
        return f"{method} {path}"
    # Fall back to the id convention: ep:<METHOD>:<path>.
    if node.id.startswith("ep:"):
        parts = node.id.split(":", 2)
        if len(parts) == 3:
            return f"{parts[1]} {parts[2]}"
    return node.id


def _entry_sources(
    graph: "KnowledgeGraph", ep_id: str, label: str
) -> list[dict[str, str]]:
    """Real doc citations for one entry point as ``[{doc, snippet}, ...]``.

    Reuses :func:`scanner.agent.assess._doc_evidence` to gather the ``doc`` nodes
    ``documents``-linked to this entry point, then quotes the route snippet (or
    the doc excerpt as a fallback) verbatim. Grounded: an item is emitted only
    when there is both a doc path and real excerpt/snippet text -- nothing is
    ever fabricated. Deduped and stably ordered.
    """
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ev in _doc_evidence(graph, [(ep_id, label)]):
        doc = _context_source(ev)
        snippet = ev.snippet or ev.excerpt
        if not doc or not isinstance(snippet, str) or not snippet.strip():
            continue
        snippet = snippet.strip()
        key = (doc, snippet)
        if key in seen:
            continue
        seen.add(key)
        sources.append({"doc": doc, "snippet": snippet})
    return sources


def _aggregate(
    assessments: list["Assessment"],
) -> tuple[str, str, str, str]:
    """Collapse several findings' assessments to one ``(value, auth, rationale,
    provenance)`` for a single entry point.

    The most-exposed / least-gated definite signal wins (see ``_EXPOSURE_RANK`` /
    ``_AUTH_RANK``); any definite signal beats ``unknown``. The rationale is
    taken verbatim from the representative assessment that carries the winning
    exposure (else the winning auth, else the first), so the explanation stays
    grounded in the agent layer's own wording. Provenance is ``"llm"`` if any
    contributing assessment used the model, else ``"offline-heuristic"``.
    """
    value = "unknown"
    authentication = "unknown"
    for a in assessments:
        if _EXPOSURE_RANK.get(a.exposure, 0) > _EXPOSURE_RANK.get(value, 0):
            value = a.exposure
        if _AUTH_RANK.get(a.authentication, 0) > _AUTH_RANK.get(authentication, 0):
            authentication = a.authentication

    representative: "Assessment | None" = None
    if value != "unknown":
        representative = next(
            (a for a in assessments if a.exposure == value), None
        )
    if representative is None and authentication != "unknown":
        representative = next(
            (a for a in assessments if a.authentication == authentication), None
        )
    if representative is None and assessments:
        representative = assessments[0]

    rationale = representative.rationale if representative is not None else ""
    provenance = (
        "llm"
        if any(a.provenance == "llm" for a in assessments)
        else "offline-heuristic"
    )
    return value, authentication, rationale, provenance


def _confidence(value: str, authentication: str, has_sources: bool) -> str:
    """Map the certainty of a verdict to ``high`` / ``medium`` / ``low``.

    A definite exposure/auth verdict backed by cited docs is ``high``; the same
    verdict with no cited doc (an inferred call) is ``medium``; with no definite
    signal at all it is ``low``.
    """
    has_signal = value != "unknown" or authentication != "unknown"
    if not has_signal:
        return "low"
    return "high" if has_sources else "medium"


def exposure_overlay(
    graph: "KnowledgeGraph",
    reachability: "ReachabilityResult",
    correlation: "CorrelationResult",
    client: "LLMClient | None" = None,
) -> dict[str, dict[str, Any]]:
    """Build the advisory EXPOSURE overlay, keyed by public entry point node id.

    For every ``entrypoint`` node in ``graph`` the overlay carries one dict::

        {
          "label": "POST /documents/import",   # method + path
          "value": "internet-facing" | "internal" | "unknown",
          "authentication": "required" | "none" | "unknown",
          "origin": "doc" | "inferred",        # doc-cited vs. llm/heuristic-only
          "confidence": "high" | "medium" | "low",
          "rationale": "...",                  # why, grounded in the docs
          "sources": [{"doc": "<relpath>", "snippet": "<verbatim excerpt>"}],
          "provenance": "llm" | "offline-heuristic",
        }

    How it is derived
    -----------------
    * :func:`scanner.agent.assess_findings` is run ONCE over the correlation's
      findings + reachability; it yields one advisory exposure ``Assessment`` per
      reachable finding (or, when there are no reachable findings, per reachable
      dependency), each stamped with the entry points it reaches. That path owns
      the model-vs-offline fallback, the doc grounding and the context gathering.
    * Those assessments are inverted into per-entry-point buckets (an entry point
      may reach several findings) and collapsed to one verdict via
      :func:`_aggregate`. Entry points that reach no assessed finding get
      ``value``/``authentication`` ``"unknown"`` with ``confidence`` ``"low"``.
    * ``sources`` are recomputed per entry point from its OWN ``documents``-linked
      docs (:func:`_entry_sources`), so every citation is a real excerpt tied to
      that route. ``origin`` is ``"doc"`` iff those sources are non-empty, else
      ``"inferred"`` -- and an inferred definite claim appends a clause saying so.

    Read-only: ``graph``, ``reachability``, ``correlation`` and every finding are
    only read; the returned dict is freshly built. Nothing is written back into
    the graph (that is Phase 2).
    """
    findings = list(getattr(correlation, "findings", None) or [])

    # The agent layer owns model/offline fallback + doc grounding. Read-only.
    assessments = assess_findings(graph, findings, reachability, client=client)

    # Map each reaching-entry-point LABEL back to its node id(s). Reachability's
    # labels are "METHOD /path" (exactly what an Assessment records), and entry
    # point ids are unique per method+path, so this inversion is unambiguous.
    label_to_ids: dict[str, list[str]] = {}
    for ep in reachability.entrypoints:
        label_to_ids.setdefault(f"{ep.method} {ep.path}", []).append(ep.id)

    buckets: dict[str, list["Assessment"]] = {}
    for a in assessments:
        for label in a.reaching_entrypoints:
            for ep_id in label_to_ids.get(label, []):
                buckets.setdefault(ep_id, []).append(a)

    overlay: dict[str, dict[str, Any]] = {}
    for node in graph.nodes_of_kind("entrypoint"):
        ep_id = node.id
        label = _entrypoint_label(node)
        sources = _entry_sources(graph, ep_id, label)
        bucket = buckets.get(ep_id, [])

        if bucket:
            value, authentication, rationale, provenance = _aggregate(bucket)
        else:
            value, authentication, provenance = "unknown", "unknown", "offline-heuristic"
            if sources:
                rationale = (
                    f"No vulnerable dependency reachable from {label} was assessed; "
                    "the linked documentation states no explicit exposure or "
                    "authentication, so exposure is left unknown."
                )
            else:
                rationale = (
                    f"No vulnerable dependency reachable from {label} was assessed "
                    "and no documentation is linked to it; exposure is unknown."
                )

        origin = "doc" if sources else "inferred"
        confidence = _confidence(value, authentication, bool(sources))

        # A definite claim with no doc citation must own that it is inferred.
        if origin == "inferred" and (value != "unknown" or authentication != "unknown"):
            rationale = rationale + _INFERRED_CLAUSE

        overlay[ep_id] = {
            "label": label,
            "value": value,
            "authentication": authentication,
            "origin": origin,
            "confidence": confidence,
            "rationale": rationale,
            "sources": sources,
            "provenance": provenance,
        }

    return overlay
