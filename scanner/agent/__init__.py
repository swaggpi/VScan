"""Agent layer: advisory, LLM-assisted exposure assessment of reachable findings.

This package is strictly advisory. It never produces a reachability verdict,
never adds or modifies a ``calls`` / ``route_to_handler`` edge, and never
overrides the deterministic analyzer / reachability / correlator output. It
reads the knowledge graph's documentation plus the reachability/vulnerability
context to judge how *exposed* a reachable finding is (internet-facing vs.
internal, authenticated vs. not) and to write a human-readable explanation.

Every result is labelled ``advisory=True`` with a ``provenance`` of ``"llm"``
(when a model is configured via ``LLM_BASE_URL`` / ``LLM_API_KEY`` /
``LLM_MODEL``) or ``"offline-heuristic"`` (the deterministic fallback used when
no model is configured or a call fails). The layer performs no network I/O
except through :class:`LLMClient`, which fails gracefully to ``None`` so the
offline path always works.
"""

from __future__ import annotations

from .assess import Assessment, assess_findings
from .client import LLMClient

__all__ = ["Assessment", "assess_findings", "LLMClient"]
