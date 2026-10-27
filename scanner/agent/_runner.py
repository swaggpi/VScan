"""Shared plumbing for the advisory agent tiers.

Two tier-agnostic pieces that every tier (exposure/assess, exploitability/triage,
dynamic-usage) needs identically:

* :func:`run_tier` -- the bounded-pool "run the LLM per item, fall back offline
  on failure, preserve order, sort" harness. This is the layer's core SAFETY
  property, so it lives in ONE place: a single item's model call failing (either
  by returning ``None`` or by raising) falls back to that item's deterministic
  offline result and never propagates; the pool is bounded at ``min(8, len)``;
  input/output order is preserved and the final sort is applied last.
* :func:`_normalize` -- coerce a model-supplied value into an allowed vocabulary,
  defaulting when it is not a recognised member.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")


def run_tier(
    items: list[_Item],
    *,
    use_llm: bool,
    llm_fn: Callable[[_Item], _Result | None],
    offline_fn: Callable[[_Item], _Result],
    sort_key: Callable[[_Result], Any],
) -> list[_Result]:
    """Run one advisory tier over ``items`` and return the sorted results.

    For each item, when ``use_llm`` is true the model path (``llm_fn``) is tried
    in a bounded thread pool; a worker that raises OR returns ``None`` yields
    ``None`` for that item so it falls back to ``offline_fn`` -- a single item's
    failure never breaks the others and nothing propagates out of the pool. The
    CPU-only offline path stays sequential. Results are kept aligned to ``items``
    by index (``executor.map`` preserves input order), so thread completion order
    never changes the output; the final order is then fixed by ``sort_key``.

    An empty ``items`` list (or ``use_llm`` false) produces results without ever
    starting a pool.
    """
    llm_results: list[_Result | None] = [None] * len(items)
    if use_llm and items:

        def _call(item: _Item) -> _Result | None:
            try:
                return llm_fn(item)
            except Exception:
                # Per-item guardrail: any worker error becomes an offline
                # fallback for this item; never propagate out of the pool.
                return None

        max_workers = min(8, len(items))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            llm_results = list(executor.map(_call, items))

    results: list[_Result] = [
        llm if llm is not None else offline_fn(item)
        for item, llm in zip(items, llm_results, strict=True)
    ]
    results.sort(key=sort_key)
    return results


def _normalize(value: Any, allowed: frozenset[str], *, default: str) -> str:
    """Coerce a model value into an allowed verdict, defaulting when unknown."""
    if isinstance(value, str) and value.strip().lower() in allowed:
        return value.strip().lower()
    return default
