"""Advisory, additive *enrichment overlays* over a warmed scan.

An enrichment overlay is an ADVISORY, read-only projection of existing scan
output onto the graph's public entry points. It never changes a finding's
``reachable`` / ``confirmed`` / ``tainted`` state or any verdict, and it never
mutates the graph or the findings -- it only *reads* them and returns a new
dict. This is Phase 1: the overlay is returned as data (served at
``GET /api/enrichment``); it is not written back into the graph.

Overlays that live here:

* **exposure** (:func:`exposure_overlay`): per public entry point, whether docs
  place it internet-facing vs. internal and whether it is auth-gated, grounded
  in the repo's documentation with provenance + citations. It promotes the
  agent layer's advisory exposure judgement (:func:`scanner.agent.assess_findings`)
  into an entry-point-keyed overlay -- "the docs say this endpoint is public, so
  it belongs on the node".
* **inferred edges** (:func:`infer_edges`) + **likely reachability**
  (:func:`likely_reachability`): a grounded LLM tier that fills *unresolved* call
  sites with inferred ``calls`` edges and, on a throwaway AUGMENTED COPY of the
  graph, surfaces dependencies that would be *likely-reachable* if those edges
  were real. Strictly additive: the inferred edges never enter the graph that
  findings/taint/verdicts read, so a likely-reachable dependency is a lead, never
  a proven verdict (see :mod:`scanner.enrich.edges`).
"""

from __future__ import annotations

from .edges import infer_edges, likely_reachability
from .exposure import exposure_overlay

__all__ = ["exposure_overlay", "infer_edges", "likely_reachability"]
