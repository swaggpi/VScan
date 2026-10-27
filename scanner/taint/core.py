"""Language-AGNOSTIC core of the sound, inter-procedural taint pass.

This module holds everything the taint pass can express WITHOUT knowing any
particular source grammar:

* the public :class:`TaintResult` and the ``tainted`` / ``not_proven`` verdicts;
* the taint-environment algebra (:data:`_Env`, :func:`_join`, :func:`_copy_env`,
  :func:`_set_env`) and the name-level bind/kill primitives
  (:func:`_bind_names`, :func:`_assign_or_kill_names`, :func:`_aug_bind_names`)
  that implement the MAY-dataflow merge and last-write-wins semantics;
* the :class:`TaintAdapter` seam -- the minimal set of per-language operations
  the driver needs;
* the driver (:func:`compute_taint`) and its per-path orchestration
  (:func:`_analyze_path`), which walk proven reachability paths and dispatch
  every grammar-specific step to the adapter that matches the path's language.

It deliberately imports NO source grammar (no ``ast``, no language analyzer):
those belong only in the per-language adapters (see :mod:`scanner.taint.python`).

THE CARDINAL RULE
-----------------
Never assert a claim unless fully proven. A MISSED taint flow is acceptable; a
FALSE "tainted" claim is a CRITICAL failure. The default verdict is
``not_proven`` (NOT "safe"/"untainted"). A dependency is only ``tainted`` when
EVERY hop from a recognised source to the sink is proven. This signal is
strictly DERIVED and ADDITIVE: the caller must never let it change
``finding.reachable``, the three-way ``verdict``, ``symbol_match``, ranking or
any pre-existing summary counter.

The merge algebra below is the soundness gate for the existential ``tainted``
claim: at a control-flow merge a name survives iff it survives on ANY incoming
path (union of provenance), so a kill on one path alone cannot refute taint, a
kill on EVERY path does, and a loop body's 0-iteration (entry) env is always
retained. The per-language propagation (how an adapter walks a function body and
drives these primitives) is documented in each adapter module.

Public entry point: :func:`compute_taint`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..graph import KnowledgeGraph
from ..reachability import ReachabilityResult

TAINTED: str = "tainted"
NOT_PROVEN: str = "not_proven"


@dataclass
class TaintResult:
    """Per-dependency taint verdict with the evidence that proves it.

    ``verdict`` is ``"tainted"`` only when a source->sink flow is fully proven;
    otherwise ``"not_proven"`` (never "safe"). The evidence fields describe the
    single proven flow (the first one found) when tainted, and are ``None`` /
    empty otherwise.
    """

    verdict: str = NOT_PROVEN
    source: str | None = None
    sink_symbol: str | None = None
    entrypoint: str | None = None
    path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _split_fn_id(fn_id: str) -> tuple[str, str] | None:
    """Split ``fn:<relpath>:<qualname>`` into ``(relpath, qualname)``.

    The relpath may itself contain no colon; the qualname may contain dots but
    no colons, so the first two colons delimit the three parts.
    """
    if not fn_id.startswith("fn:"):
        return None
    rest = fn_id[3:]
    idx = rest.rfind(":")
    if idx < 0:
        return None
    return rest[:idx], rest[idx + 1 :]


# --------------------------------------------------------------------------
# Taint-environment algebra (grammar-free)
# --------------------------------------------------------------------------

# A taint environment maps a tainted name -> the set of source descriptors that
# can reach it (its provenance). A name is tainted iff present with a non-empty
# set.
_Env = dict[str, set[str]]


def _bind_names(names: list[str], taint: set[str], env: _Env) -> None:
    """Mark each name in ``names`` tainted with ``taint`` (union, never kills).

    Used for binds that can only ADD taint (e.g. a comprehension target drawing
    from a tainted iterable). An empty ``taint`` is a no-op. The adapter supplies
    the simple names a target binds; a target binding no simple name yields an
    empty list and therefore no change.
    """
    if not taint:
        return
    for name in names:
        env.setdefault(name, set()).update(taint)


def _assign_or_kill_names(names: list[str], taint: set[str], env: _Env) -> None:
    """Last-write-wins bind of ``names``: set tainted, or KILL when not tainted.

    Each name takes ``taint`` directly when non-empty, and is removed from
    ``env`` when ``taint`` is empty (a rebind to a constant kills the name). The
    adapter supplies the simple names a target binds; a target that binds no bare
    name (e.g. a subscript/attribute assignment) yields an empty list and so must
    NOT kill a same-named variable -- which the empty list guarantees.
    """
    for name in names:
        if taint:
            env[name] = set(taint)
        else:
            env.pop(name, None)


def _aug_bind_names(names: list[str], rhs_taint: set[str], env: _Env) -> None:
    """``x += y``: each name stays/becomes tainted if was-tainted OR rhs-tainted.

    Never kills (augmented assignment reads the old value), matching ``+=``.
    """
    for name in names:
        combined = set(env.get(name, set())) | rhs_taint
        if combined:
            env[name] = combined


def _copy_env(env: _Env) -> _Env:
    return {name: set(provs) for name, provs in env.items()}


def _join(*envs: _Env) -> _Env:
    """May-dataflow JOIN of taint environments at a control-flow merge.

    A name is present in the result iff it is present with non-empty provenance
    in ANY input env; its provenance is the UNION over the inputs that carry it.
    This is the sound merge for the existential ``tainted`` claim: taint survives
    a merge when it survives on any incoming path, and dies only when EVERY
    incoming path killed it. Returns a fresh env with fresh provenance sets.
    """
    out: _Env = {}
    for env in envs:
        for name, provs in env.items():
            if provs:
                if name in out:
                    out[name] |= set(provs)
                else:
                    out[name] = set(provs)
    return out


def _set_env(env: _Env, new: _Env) -> None:
    """Replace ``env``'s contents in place with (copies of) ``new``'s.

    Callers hold a live reference to ``env`` across the flow walk, so a merge
    must mutate it in place rather than rebind it.
    """
    env.clear()
    for name, provs in new.items():
        env[name] = set(provs)


# --------------------------------------------------------------------------
# Per-language adapter seam
# --------------------------------------------------------------------------


@runtime_checkable
class TaintAdapter(Protocol):
    """The minimal per-language operations the driver needs.

    The driver is grammar-free: for a given proven path it selects the adapter
    whose :meth:`language_matches` accepts the path's function files, then drives
    the whole hop-by-hop analysis through the methods below. Everything
    grammar-specific (parsing, source/sink recognition, flow-sensitive
    propagation, argument->parameter binding, call-site resolution) lives behind
    this seam; the adapter uses the core env algebra (``_join`` /
    ``_assign_or_kill_names`` / ...) for its merges and kills.

    The ``cache`` and ``fn_info`` objects are OPAQUE to the driver: an adapter
    returns whatever it needs from :meth:`make_cache` / :meth:`resolve_function`
    and receives those same objects back. The driver never inspects them.
    """

    def language_matches(self, relpath: str) -> bool:
        """True if this adapter handles the source file at ``relpath``."""
        ...

    def make_cache(self, repo_root: str) -> Any:
        """Build an opaque per-repo parse cache for this adapter."""
        ...

    def resolve_function(self, cache: Any, fn_id: str) -> Any | None:
        """Resolve a path node id to opaque function info, or ``None``.

        ``None`` means the function could not be parsed/located, so the path is
        not analysable -> the dependency stays ``not_proven``.
        """
        ...

    def handler_seed(self, fn_info: Any) -> _Env:
        """Seed the initial tainted-name env for the handler (first on-path fn)."""
        ...

    def bind_into_next(self, caller_info: Any, env: _Env, next_info: Any) -> _Env:
        """Walk the caller and return the seed env bound into the next function.

        Taint is bound ONLY from call sites proven to target ``next_info``, using
        the taint state at each such call's position.
        """
        ...

    def detect_sink(
        self, sink_info: Any, env: _Env, dep_symbols: set[str]
    ) -> tuple[str, str] | None:
        """Prove a tainted argument into a ``dep_symbols`` call at the sink fn.

        Returns the first ``(sink_symbol, source_descriptor)`` found, else
        ``None``.
        """
        ...


def _select_adapter(
    adapters: tuple[TaintAdapter, ...], fn_id: str
) -> TaintAdapter | None:
    """Pick the adapter whose language matches ``fn_id``'s file, else ``None``.

    A proven reachability path's functions are all one language, so the first
    function's relpath selects the adapter for the whole path. If no adapter
    matches (e.g. a ``.js`` file today, with only the Python adapter wired in)
    the path is not analysable -> ``not_proven`` (exactly the current effective
    behaviour, since parsing a non-Python file used to fail).
    """
    split = _split_fn_id(fn_id)
    if split is None:
        return None
    relpath, _ = split
    for adapter in adapters:
        if adapter.language_matches(relpath):
            return adapter
    return None


# --------------------------------------------------------------------------
# Per-path analysis (grammar-free orchestration)
# --------------------------------------------------------------------------


def _analyze_path(
    adapters: tuple[TaintAdapter, ...],
    caches: dict[int, Any],
    repo_root: str,
    ep_label: str,
    dep_symbols: set[str],
    example_path: list[str],
) -> TaintResult | None:
    """Prove (or fail to prove) a flow along one reachability example path.

    ``example_path`` is ``[ep_id, fn_0, ..., fn_{k-1}, dep_id]``. Returns a
    ``tainted`` :class:`TaintResult` when a source at the handler reaches the
    dependency sink in ``fn_{k-1}``, else ``None``. All grammar-specific steps go
    through the adapter selected for the path's language.
    """
    fn_ids = [n for n in example_path if n.startswith("fn:")]
    if not fn_ids:
        return None

    adapter = _select_adapter(adapters, fn_ids[0])
    if adapter is None:
        return None
    key = id(adapter)
    cache = caches.get(key)
    if cache is None:
        cache = adapter.make_cache(repo_root)
        caches[key] = cache

    # Resolve every function on the path up front; bail (unproven) if any is
    # missing or unparseable.
    resolved: list[Any] = []
    for fn_id in fn_ids:
        info = adapter.resolve_function(cache, fn_id)
        if info is None:
            return None
        resolved.append(info)

    # Handler: seed its own route parameters / request sources.
    env: _Env = adapter.handler_seed(resolved[0])

    # Walk each hop, binding taint that provably reaches the next function into
    # its parameters (flow-sensitively, at each proven call site).
    for index in range(len(resolved) - 1):
        env = adapter.bind_into_next(resolved[index], env, resolved[index + 1])

    flow = adapter.detect_sink(resolved[-1], env, dep_symbols)
    if flow is None:
        return None
    sink_symbol, source = flow
    return TaintResult(
        verdict=TAINTED,
        source=source,
        sink_symbol=sink_symbol,
        entrypoint=ep_label,
        path=list(example_path),
    )


# --------------------------------------------------------------------------
# Public entry point (driver)
# --------------------------------------------------------------------------


def compute_taint(
    graph: KnowledgeGraph,
    reach: ReachabilityResult,
    repo_root: str,
    adapters: tuple[TaintAdapter, ...],
) -> dict[str, TaintResult]:
    """Compute the per-dependency taint signal, keyed by dependency id.

    For every dependency reached from a public entry point, this asks whether
    attacker-controlled input at the handler flows into the call(s) into that
    dependency. A dependency is ``tainted`` if ANY of its reaching paths proves
    a flow; otherwise ``not_proven``. Only reached dependencies appear in the
    result -- a dependency with no reaching path can never be tainted, so the
    caller's default (``not_proven``) already covers it.

    The computation is pure and offline: each proven reachability path is handed
    to the first ``adapters`` entry whose language matches, which re-parses the
    source of the functions on that path. ``repo_root`` must be the absolute path
    of the scanned repository (file node ids carry only repo-relative paths).
    """
    caches: dict[int, Any] = {}
    results: dict[str, TaintResult] = {}

    for ep in reach.entrypoints:
        ep_node = graph.get_node(ep.id)
        if ep_node is not None and ep_node.attrs.get("unresolved_handler"):
            # An opaque handler we cannot step into: nothing is proven here.
            continue
        ep_label = f"{ep.method} {ep.path}"
        for dep in ep.reachable_dependencies:
            dep_id = dep.id
            results.setdefault(dep_id, TaintResult())
            if results[dep_id].verdict == TAINTED:
                continue  # already proven by an earlier path
            dep_symbols = set(dep.symbols)
            if dep.symbol:
                dep_symbols.add(dep.symbol)
            if not dep_symbols:
                continue
            proven = _analyze_path(
                adapters, caches, repo_root, ep_label, dep_symbols, dep.example_path
            )
            if proven is not None:
                results[dep_id] = proven

    return results
