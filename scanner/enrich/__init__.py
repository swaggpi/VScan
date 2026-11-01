"""Advisory, additive *enrichment overlays* over a warmed scan.

An enrichment overlay is an ADVISORY, read-only projection of existing scan
output onto the graph's public entry points. It never changes a finding's
``reachable`` / ``confirmed`` / ``tainted`` state or any verdict, and it never
mutates the graph or the findings -- it only *reads* them and returns a new
dict. This is Phase 1: the overlay is returned as data (served at
``GET /api/enrichment``); it is not written back into the graph.

Currently one overlay lives here:

* **exposure** (:func:`exposure_overlay`): per public entry point, whether docs
  place it internet-facing vs. internal and whether it is auth-gated, grounded
  in the repo's documentation with provenance + citations. It promotes the
  agent layer's advisory exposure judgement (:func:`scanner.agent.assess_findings`)
  into an entry-point-keyed overlay -- "the docs say this endpoint is public, so
  it belongs on the node".
"""

from __future__ import annotations

from .exposure import exposure_overlay

__all__ = ["exposure_overlay"]
