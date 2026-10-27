"""Sound, lightweight, inter-procedural taint pass (layer 1).

This pass answers ONE question, and only when it can prove it:

    Does attacker-controlled input at a web entry handler flow, hop by hop,
    into a call that lands in a vulnerable dependency?

It runs on top of the reachability engine: reachability has already proven a
hop-by-hop path ``entrypoint -> handler -> ... -> dependency`` for every reached
dependency (``ReachedDependency.example_path``). This pass re-parses the source
of the functions ON that proven path and checks whether a *source* (an
attacker-controlled read at the handler) propagates -- through taint-preserving
operations and proven argument/parameter bindings -- all the way into the
*sink* (the call into the dependency).

The pass is split into a language-AGNOSTIC core (:mod:`scanner.taint.core` --
the driver, the env/join algebra, the soundness gate and the
:class:`~scanner.taint.core.TaintAdapter` seam) and per-language adapters. Today
the only adapter is :class:`scanner.taint.python.PythonTaintAdapter`; a path
whose functions are not matched by any adapter is simply not analysable and
stays ``not_proven``.

Public entry point: :func:`compute_taint`. The public surface
(``compute_taint``, :class:`TaintResult`, ``TAINTED``, ``NOT_PROVEN``) is
unchanged from the pre-split module.
"""

from __future__ import annotations

from ..graph import KnowledgeGraph
from ..reachability import ReachabilityResult
from .core import (
    NOT_PROVEN,
    TAINTED,
    TaintAdapter,
    TaintResult,
    _split_fn_id,
)
from .core import compute_taint as _compute_taint
from .javascript import JavaScriptTaintAdapter
from .python import (
    PythonTaintAdapter,
    _bind_call_args,
    _call_resolves_to,
    _import_aliases,
    _ParsedFile,
    _propagate,
    _reconstruct_dotted,
    _source_of,
    _taint_of_expr,
)

# The adapter registry, in priority order. Each proven path is handled by the
# first adapter whose language matches the path's function files. Adding a new
# language means appending its adapter here -- the core driver is untouched.
_ADAPTERS: tuple[TaintAdapter, ...] = (
    PythonTaintAdapter(),
    JavaScriptTaintAdapter(),
)


def compute_taint(
    graph: KnowledgeGraph, reach: ReachabilityResult, repo_root: str
) -> dict[str, TaintResult]:
    """Compute the per-dependency taint signal, keyed by dependency id.

    Thin wrapper over :func:`scanner.taint.core.compute_taint` that supplies the
    wired-in adapter registry. The signature and behaviour are unchanged from the
    pre-split module: ``repo_root`` must be the absolute path of the scanned
    repository.
    """
    return _compute_taint(graph, reach, repo_root, _ADAPTERS)


__all__ = [
    "NOT_PROVEN",
    "TAINTED",
    "TaintAdapter",
    "TaintResult",
    "PythonTaintAdapter",
    "JavaScriptTaintAdapter",
    "compute_taint",
    # Re-exported internals, kept importable from ``scanner.taint`` for the test
    # suite (unit tests exercise these grammar-specific helpers directly).
    "_ParsedFile",
    "_bind_call_args",
    "_call_resolves_to",
    "_import_aliases",
    "_propagate",
    "_reconstruct_dotted",
    "_source_of",
    "_split_fn_id",
    "_taint_of_expr",
]
