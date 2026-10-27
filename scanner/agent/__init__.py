"""Agent layer: advisory, LLM-assisted judgements about reachable/vulnerable deps.

This package is strictly advisory. It never produces a reachability verdict,
never adds or modifies a ``calls`` / ``route_to_handler`` edge, and never
overrides the deterministic analyzer / reachability / correlator output -- it
only reads the knowledge graph plus the reachability/vulnerability context. It
exposes three independent tiers:

* **exposure assessment** (:func:`assess_findings`): how *exposed* a reachable
  finding is (internet-facing vs. internal, authenticated vs. not), with a
  human-readable explanation grounded in the repo's doc corpus.
* **exploitability triage** (:func:`triage_findings`): whether the symbols the
  project actually calls line up with the CVE's affected sink.
* **dynamic-usage investigation** (:func:`investigate_usage`): for vulnerable
  deps with no resolved static call edge, where/how the dependency's
  name/module appears in the repo.

Every result is labelled ``advisory=True`` with a ``provenance`` of ``"llm"``
(when a model is configured via ``LLM_BASE_URL`` / ``LLM_API_KEY`` /
``LLM_MODEL``) or ``"offline-heuristic"`` (the deterministic fallback used when
no model is configured or a call fails). Model I/O goes only through
:class:`LLMClient`, which fails gracefully to ``None`` so the offline path
always works. Beyond that, the dynamic-usage tier additionally re-walks the
repo filesystem (via :func:`scanner.walker.walk_repo`, into a throwaway graph)
to gather its textual evidence; no other tier touches the filesystem or network.
"""

from __future__ import annotations

from .assess import Assessment, assess_findings
from .client import LLMClient
from .triage import Triage, triage_findings
from .usage import Usage, investigate_usage

__all__ = [
    "Assessment",
    "assess_findings",
    "LLMClient",
    "Triage",
    "triage_findings",
    "Usage",
    "investigate_usage",
]
