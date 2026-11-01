"""Grounded INFERRED-EDGE tier (Phase 2): fill unresolved call sites + a
"likely" reachability view -- WITHOUT ever touching the proven graph.

The structural scan honestly refuses to guess: a call it cannot soundly resolve
is recorded on the source function as ``attrs["unresolved_calls"]`` (and counted
in ``attrs["unresolved_call_count"]``) and NEVER turned into an edge. That keeps
reachability/taint/verdicts sound, but it also leaves gaps -- a dependency may
look unreachable only because the one call site that reaches it was a dynamic
dispatch we could not read.

This module fills those gaps *advisorily*. For each function with unresolved
calls it builds a small, GROUNDED candidate shortlist of real node ids the call
could plausibly resolve to -- project functions/deps whose name tokens overlap
the call, plus the dependencies the calling function's module demonstrably
imports (so a dynamic method call like ``image.resize`` can resolve to the
library it dispatches to, Pillow) -- asks the model to map
each unresolved call to ONE id from that shortlist (or ``null``), validates the
answer hard against the shortlist + the real graph, and emits the accepted
mappings as an OVERLAY of inferred ``calls`` edges. The overlay is pure data --
it is NEVER added to the graph that findings / taint / symbol_match read.

:func:`likely_reachability` then answers "what would be reachable IF these
inferred edges were real?" on a throwaway AUGMENTED COPY of the graph, and
DIFFs that against the proven reachability to surface *likely-reachable*
dependencies. A likely-reachable dependency is a lead, never a verdict: it can
never upgrade anything to proven reachable / confirmed / tainted / exploitable.

The cardinal-rule firewall (why proven output is byte-identical)
----------------------------------------------------------------
* :func:`infer_edges` is strictly READ-ONLY over ``graph`` -- it calls
  ``graph.nodes`` / ``get_node`` / ``has_node`` / ``edges`` and reads node
  ``attrs``, and it NEVER calls ``graph.add_edge`` / ``add_node`` or mutates any
  node's ``attrs``. Its result is a brand-new list of plain dicts.
* :func:`likely_reachability` runs on ``copy.deepcopy(graph)`` (a fully
  independent object -- ``KnowledgeGraph`` holds only plain dict/list/set state,
  so a deepcopy is clean and preserves the ``_edge_keys`` dedup index). The
  inferred edges are added to the COPY only; the original graph object is never
  touched, so the canonical ``graph -> compute_reachability -> correlate ->
  compute_taint`` pipeline produces identical findings/taint/verdicts whether or
  not inference ran.
* Hard validation rejects any proposed target that was not in the shortlist or
  is absent from the graph (hallucinated/invented ids), self-loops, and edges
  that already exist deterministically.

Offline / unavailable client (:meth:`LLMClient.available` false, or ``None``) ->
:func:`infer_edges` returns ``[]`` and :func:`likely_reachability` surfaces
nothing. No API key, no inference; the proven output is unchanged either way.
"""

from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING, Any

from ..reachability import compute_reachability

if TYPE_CHECKING:  # avoid hard import cycles / heavy deps at import time
    from ..agent import LLMClient
    from ..correlate import CorrelationResult
    from ..graph import KnowledgeGraph, Node
    from ..reachability import ReachabilityResult

# Node kinds an unresolved call could plausibly resolve to (the grounding set).
_TARGET_KINDS = frozenset({"function", "dependency"})

# Keep the shortlist (the grounding boundary) small and cheap.
_MAX_CANDIDATES = 20

# Confidence vocabulary + rank (shared with the overlay/likely entries).
_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}

_SYSTEM_PROMPT = (
    "You are a precise static-analysis assistant resolving dynamic call sites in "
    "a code graph. For each unresolved call you are given a SHORTLIST of real "
    "candidate target nodes. You may ONLY choose a target whose id appears in "
    "that call's shortlist, or null if none is a plausible target. Never invent "
    "an id. Prefer null over a weak guess. A call is often a method/attribute "
    "call on a value (e.g. `image.resize`, `pool.request`, `client.connect`); "
    "map it to a candidate marked '(imported by this module)' when the call "
    "plausibly dispatches to that dependency's API, and to a project function "
    "when the name matches one. Map a call to a dependency ONLY when it is a "
    "genuine use of that library -- a plain dict/list/stdlib call (e.g. "
    "`body.get`, `uuid.uuid4`) is null. Reply with STRICT JSON only: "
    '{"mappings": [{"call": "<exact call text>", "target": "<node id or null>", '
    '"confidence": "high|medium|low", "rationale": "<one short sentence>"}]}'
)


def _tokenize(text: str) -> set[str]:
    """Lower-cased alphanumeric tokens from ``text`` (camelCase split, len>=2).

    ``"yaml.load"`` -> ``{"yaml", "load"}``; ``"PyYAML"`` -> ``{"py", "yaml"}``;
    ``"process_import"`` -> ``{"process", "import"}``. Single-character tokens are
    dropped as noise. Pure string logic; reads nothing from the graph.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return {t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if len(t) >= 2}


def _call_token(expr: str) -> str:
    """The callee token of an unresolved call expression (text before ``(``).

    ``"self.process(data)"`` -> ``"self.process"``; a bare name is returned
    as-is. Never fabricated -- it is a slice of the recorded call text.
    """
    head = expr.strip().split("(", 1)[0].strip()
    return head or expr.strip()


def _calling_file(node: "Node") -> str:
    """The relpath of the file that holds a function node (grounding source).

    Prefers the node's ``relpath`` attr (what the analyzers stamp on every
    function node); falls back to parsing the ``fn:<relpath>:<qualname>`` id so a
    file is always produced, never invented.
    """
    relpath = node.attrs.get("relpath")
    if isinstance(relpath, str) and relpath:
        return relpath
    if node.id.startswith("fn:"):
        parts = node.id.split(":", 2)
        if len(parts) == 3:
            return parts[1]
    return node.id


class _Candidate:
    """One real target node on a call's shortlist, with its match strength."""

    __slots__ = ("id", "name", "kind", "score", "strength", "imported")

    def __init__(
        self,
        id: str,
        name: str,
        kind: str,
        score: int,
        strength: str,
        imported: bool = False,
    ):
        self.id = id
        self.name = name
        self.kind = kind
        self.score = score
        self.strength = strength
        # True when this candidate is a dependency the calling function's module
        # demonstrably imports (the grounding for dynamic dep-dispatch).
        self.imported = imported


def _candidate_nodes(graph: "KnowledgeGraph") -> list[tuple["Node", set[str]]]:
    """Real function/dependency nodes paired with their name tokens (grounding).

    Abstract function declarations are excluded -- they are not themselves
    reachable call targets (mirrors the reachability engine's own treatment).
    """
    out: list[tuple["Node", set[str]]] = []
    for node in graph.nodes:
        if node.kind not in _TARGET_KINDS:
            continue
        if node.attrs.get("abstract"):
            continue
        tokens = _tokenize(node.name)
        if tokens:
            out.append((node, tokens))
    return out


def _module_from_relpath(relpath: str) -> str:
    """Best-effort module name from a file relpath (``a/b.py`` -> ``a.b``)."""
    if relpath.endswith(".py"):
        relpath = relpath[:-3]
    return relpath.strip("/").replace("/", ".")


def _module_imported_deps(graph: "KnowledgeGraph") -> dict[str, list["Node"]]:
    """Map each module name -> the dependency nodes it imports (grounding).

    Built from the deterministic ``imports`` edges (``mod:<module> ->
    dep:<...>``). This is the grounding for dynamic dependency dispatch: a
    method/attribute call the scan could not read (``image.resize``) may
    dispatch to a dependency the module demonstrably imports (Pillow).
    """
    out: dict[str, list["Node"]] = {}
    for e in graph.edges:
        if e.kind != "imports" or not e.src.startswith("mod:"):
            continue
        if not e.dst.startswith("dep:"):
            continue
        dep = graph.get_node(e.dst)
        if dep is None:
            continue
        bucket = out.setdefault(e.src[len("mod:") :], [])
        if dep not in bucket:
            bucket.append(dep)
    return out


def _imported_deps_for(
    fn: "Node", module_imports: dict[str, list["Node"]]
) -> list["Node"]:
    """The dependency nodes imported by the module that holds ``fn``.

    Primary key is the function's ``module`` attr; falls back to deriving the
    module from its relpath so a function still gets its real imported deps.
    """
    module = fn.attrs.get("module")
    if isinstance(module, str) and module in module_imports:
        return module_imports[module]
    return module_imports.get(_module_from_relpath(_calling_file(fn)), [])


def _shortlist(
    call: str,
    candidate_nodes: list[tuple["Node", set[str]]],
    vuln_dep_ids: set[str],
    src_id: str,
    imported_deps: list["Node"],
) -> list[_Candidate]:
    """The grounded candidate shortlist for one unresolved call.

    Two grounding signals feed it:

    * **name/symbol token overlap** -- a project function (or dependency) whose
      name tokens overlap the call's tokens. A function can be ``high`` strength
      (a near-exact name match is near-certain); a dependency is capped at
      ``medium`` because a name match alone does not prove dispatch.
    * **module-imported dependencies** -- every dependency the calling function's
      module demonstrably imports, offered as a ``medium`` candidate regardless
      of token overlap. This is what lets a dynamic method call (``image.resize``)
      resolve to the dependency it dispatches to (Pillow): inferred, never
      near-certain, so never ``high``.

    The calling function itself is never a candidate (no self-loop). Ranked by
    score desc, vulnerable deps first, then id; capped at
    :data:`_MAX_CANDIDATES`.
    """
    call_tokens = _tokenize(_call_token(call)) | _tokenize(call)
    by_id: dict[str, _Candidate] = {}
    if call_tokens:
        for node, node_tokens in candidate_nodes:
            if node.id == src_id:
                continue
            overlap = call_tokens & node_tokens
            if not overlap:
                continue
            score = len(overlap)
            strong = node_tokens <= call_tokens or score >= 2
            strength = "high" if strong else "medium"
            if node.kind == "dependency":
                # A dependency name match alone is not near-certain dispatch.
                strength = "medium"
            by_id[node.id] = _Candidate(
                node.id, node.name, node.kind, score, strength, imported=False
            )
    # Module-imported dependencies: the grounding for dynamic dep-dispatch.
    for dep in imported_deps:
        if dep.id == src_id:
            continue
        existing = by_id.get(dep.id)
        if existing is not None:
            existing.imported = True
            continue
        by_id[dep.id] = _Candidate(dep.id, dep.name, dep.kind, 1, "medium", imported=True)
    scored = list(by_id.values())
    scored.sort(key=lambda c: (-c.score, c.id not in vuln_dep_ids, c.id))
    return scored[:_MAX_CANDIDATES]


def _combine_confidence(strength: str, model_conf: str | None) -> str:
    """Weaker of the match strength and the model's stated certainty.

    Match strength and model certainty are both bounded signals; taking the
    weaker one keeps an inferred edge from claiming more confidence than either
    source supports. An absent/invalid model confidence defaults to ``medium``.
    """
    mc = model_conf if model_conf in _CONFIDENCE_VALUES else "medium"
    return strength if _CONF_RANK[strength] <= _CONF_RANK[mc] else mc


def _available(client: "LLMClient | None") -> bool:
    """True iff a usable model client was passed (never raises)."""
    if client is None:
        return False
    try:
        return bool(client.available())
    except Exception:  # noqa: BLE001 - a flaky client is just "unavailable"
        return False


def _build_user_prompt(
    fn: "Node", call_candidates: dict[str, list[_Candidate]]
) -> str:
    """Render the per-function user prompt: signature + each call's shortlist."""
    signature = fn.attrs.get("signature")
    lines = [f"Calling function: {fn.name}"]
    if isinstance(signature, str) and signature:
        lines.append(f"Signature: {signature}")
    lines.append(f"File: {_calling_file(fn)}")
    lines.append("")
    lines.append(
        "Unresolved calls and their candidate targets (choose one id per call "
        "from that call's list, or null):"
    )
    for call, cands in call_candidates.items():
        lines.append(f"- call: {call}")
        for c in cands:
            tag = " (imported by this module)" if c.imported else ""
            lines.append(f"    * id={c.id}  name={c.name}  kind={c.kind}{tag}")
    return "\n".join(lines)


def _ask_model(
    client: "LLMClient",
    fn: "Node",
    call_candidates: dict[str, list[_Candidate]],
) -> list[dict[str, Any]]:
    """Ask the model to map this function's unresolved calls; never raises.

    Returns a list of ``{call, target, confidence, rationale}`` dicts exactly as
    the model proposed (validation happens in the caller). Any transport error,
    unavailable model, or malformed body collapses to ``[]``.
    """
    user = _build_user_prompt(fn, call_candidates)
    try:
        data = client.complete_json(_SYSTEM_PROMPT, user)
    except Exception:  # noqa: BLE001 - the client contract is to return None, but be safe
        return []
    if not isinstance(data, dict):
        return []
    mappings = data.get("mappings")
    if not isinstance(mappings, list):
        return []
    out: list[dict[str, Any]] = []
    for m in mappings:
        if not isinstance(m, dict):
            continue
        call = m.get("call")
        target = m.get("target")
        if not isinstance(call, str):
            continue
        if target is not None and not isinstance(target, str):
            continue
        conf = m.get("confidence")
        rationale = m.get("rationale")
        out.append(
            {
                "call": call,
                "target": target,
                "confidence": conf if isinstance(conf, str) else None,
                "rationale": rationale if isinstance(rationale, str) else "",
            }
        )
    return out


def infer_edges(
    graph: "KnowledgeGraph",
    reachability: "ReachabilityResult",
    correlation: "CorrelationResult",
    client: "LLMClient | None" = None,
) -> list[dict[str, Any]]:
    """Grounded overlay of INFERRED ``calls`` edges for unresolved call sites.

    For every function node carrying ``attrs["unresolved_calls"]`` a grounded
    candidate shortlist is built per call (:func:`_shortlist`); the model maps
    each call to ONE shortlisted id (or null); each accepted mapping becomes an
    overlay entry::

        {
          "src": "fn:app/views.py:import_doc",   # calling function node id
          "dst": "dep:PyPI:PyYAML",              # a REAL shortlisted target id
          "kind": "calls",
          "symbol": "loader.load",               # the call token (grounding)
          "origin": "inferred",
          "confidence": "high" | "medium" | "low",
          "rationale": "...",                    # why this mapping
          "sources": [{"file": "<relpath>", "snippet": "<unresolved call text>"}],
        }

    Hard validation (the firewall boundary): a proposed ``dst`` is accepted only
    when it was on THAT call's shortlist AND exists in ``graph``; self-loops and
    edges already present deterministically (any ``calls`` edge ``src -> dst``)
    are skipped; duplicate inferred ``(src, dst, symbol)`` entries are collapsed.

    READ-ONLY over ``graph`` -- it never calls ``add_edge``/``add_node`` and
    never mutates a node's ``attrs``. With no usable client it returns ``[]``.
    ``reachability`` is accepted for parity with the other overlays;
    ``correlation`` is used only to order the shortlist (vulnerable deps first).
    """
    if not _available(client):
        return []
    assert client is not None  # for type-checkers; guarded by _available

    findings = list(getattr(correlation, "findings", None) or [])
    vuln_dep_ids = {
        f.dependency_id for f in findings if getattr(f, "dependency_id", None)
    }

    candidate_nodes = _candidate_nodes(graph)
    module_imports = _module_imported_deps(graph)
    existing_calls = {
        (e.src, e.dst) for e in graph.edges if e.kind == "calls"
    }

    overlay: list[dict[str, Any]] = []
    emitted: set[tuple[str, str, str]] = set()

    functions = [
        n
        for n in graph.nodes
        if n.kind == "function" and isinstance(n.attrs.get("unresolved_calls"), list)
    ]
    for fn in sorted(functions, key=lambda n: n.id):
        calls = [c for c in fn.attrs["unresolved_calls"] if isinstance(c, str) and c.strip()]
        imported_deps = _imported_deps_for(fn, module_imports)
        call_candidates: dict[str, list[_Candidate]] = {}
        for call in calls:
            cands = _shortlist(
                call, candidate_nodes, vuln_dep_ids, fn.id, imported_deps
            )
            if cands:
                call_candidates[call] = cands
        if not call_candidates:
            continue

        for mapping in _ask_model(client, fn, call_candidates):
            call = mapping["call"]
            target = mapping["target"]
            if not isinstance(target, str) or not target:
                continue  # model declined (null) -> no edge
            cands = call_candidates.get(call)
            if cands is None:
                continue  # model echoed a call we did not ask about -> ignore
            by_id = {c.id: c for c in cands}
            # Reject hallucinated/out-of-shortlist ids and anything not in graph.
            if target not in by_id or not graph.has_node(target):
                continue
            if target == fn.id:
                continue  # no self-loops
            if (fn.id, target) in existing_calls:
                continue  # already proven deterministically -> adds nothing
            token = _call_token(call)
            key = (fn.id, target, token)
            if key in emitted:
                continue
            emitted.add(key)

            cand = by_id[target]
            confidence = _combine_confidence(cand.strength, mapping["confidence"])
            rationale = mapping["rationale"].strip() or (
                f"Model resolved unresolved call `{call}` to {cand.name} "
                f"({cand.kind}) from the candidate shortlist."
            )
            sources = [{"file": _calling_file(fn), "snippet": call.strip()}]
            if cand.imported:
                # Ground a dynamic dep-dispatch edge in the module's own import.
                sources.append(
                    {
                        "file": _calling_file(fn),
                        "snippet": f"module imports {cand.name}",
                    }
                )
            overlay.append(
                {
                    "src": fn.id,
                    "dst": target,
                    "kind": "calls",
                    "symbol": token,
                    "origin": "inferred",
                    "confidence": confidence,
                    "rationale": rationale,
                    "sources": sources,
                }
            )

    overlay.sort(key=lambda e: (e["src"], e["dst"], e["symbol"]))
    return overlay


def _weakest(confidences: list[str]) -> str:
    """The lowest-rank confidence in the list (``low`` when empty)."""
    ranked = [c for c in confidences if c in _CONFIDENCE_VALUES]
    if not ranked:
        return "low"
    return min(ranked, key=lambda c: _CONF_RANK[c])


def _example_inferred_path(
    augmented_reach: "ReachabilityResult",
    dep_id: str,
    inferred_pairs: set[tuple[str, str]],
    edge_conf: dict[tuple[str, str], str],
) -> tuple[list[str] | None, list[str]]:
    """An example augmented path to ``dep_id`` that traverses an inferred edge.

    Scans each entry point's reached dependencies for ``dep_id`` and inspects its
    ``example_path`` (entrypoint -> ... -> dep). Returns the first path whose
    consecutive node pairs include at least one inferred edge, plus the
    confidences of the inferred edges it crosses. Since a likely-reachable dep is
    by construction NOT proven-reachable, every augmented path to it must cross
    an inferred edge, so a match is expected; ``(None, [])`` is a defensive
    fallback only.
    """
    for ep in augmented_reach.entrypoints:
        for dep in ep.reachable_dependencies:
            if dep.id != dep_id:
                continue
            path = dep.example_path
            used = [
                (path[i], path[i + 1])
                for i in range(len(path) - 1)
                if (path[i], path[i + 1]) in inferred_pairs
            ]
            if used:
                return list(path), [edge_conf.get(p, "low") for p in used]
    return None, []


def likely_reachability(
    graph: "KnowledgeGraph",
    inferred_edges: list[dict[str, Any]],
    proven_reachability: "ReachabilityResult",
) -> dict[str, Any]:
    """"Likely" reachability: what the inferred edges WOULD add, on a COPY.

    Builds an AUGMENTED COPY of ``graph`` (``copy.deepcopy`` -- a clean,
    independent object), adds the inferred ``calls`` edges to the COPY only, runs
    the canonical :func:`compute_reachability` on it, and DIFFs the result
    against ``proven_reachability``. The returned ``likely_reachable`` list holds
    exactly the dependencies reachable in the augmented copy but NOT in the
    proven result -- each a *lead*, never a verdict::

        {
          "likely_reachable": [
            {
              "dependency_id": "dep:PyPI:PyYAML",
              "name": "PyYAML",
              "confidence": "high" | "medium" | "low",  # weakest inferred edge on the path
              "via": ["ep:POST:/import", "fn:...", "dep:PyPI:PyYAML"],  # >=1 inferred edge
            }
          ],
          "inferred_edges": [ ... the overlay entries, echoed back ... ],
        }

    The original ``graph`` object and ``proven_reachability`` are NEVER modified
    (the firewall): an inferred edge may surface a likely-reachable dependency
    but can never upgrade anything to proven reachable/confirmed/tainted. With no
    inferred edges the augmented copy equals the original, so ``likely_reachable``
    is empty.
    """
    augmented = copy.deepcopy(graph)
    inferred_pairs: set[tuple[str, str]] = set()
    edge_conf: dict[tuple[str, str], str] = {}
    for e in inferred_edges:
        if e.get("kind") != "calls":
            continue
        src = e.get("src")
        dst = e.get("dst")
        if not (isinstance(src, str) and isinstance(dst, str)):
            continue
        if not (augmented.has_node(src) and augmented.has_node(dst)):
            continue
        augmented.add_edge(
            src, dst, "calls", symbol=e.get("symbol") or "", origin="inferred"
        )
        inferred_pairs.add((src, dst))
        conf = e.get("confidence")
        edge_conf[(src, dst)] = conf if conf in _CONFIDENCE_VALUES else "low"

    augmented_reach = compute_reachability(augmented)
    proven_ids = {d["id"] for d in proven_reachability.repo.reachable_deps}

    likely: list[dict[str, Any]] = []
    for dep in augmented_reach.repo.reachable_deps:
        dep_id = dep["id"]
        if dep_id in proven_ids:
            continue  # already proven reachable -> not a new "likely" lead
        via, confidences = _example_inferred_path(
            augmented_reach, dep_id, inferred_pairs, edge_conf
        )
        if via is None:
            continue  # defensive: a new dep must have an inferred path
        likely.append(
            {
                "dependency_id": dep_id,
                "name": dep.get("name", dep_id),
                "confidence": _weakest(confidences),
                "via": via,
            }
        )

    likely.sort(key=lambda x: (x["name"], x["dependency_id"]))
    return {"likely_reachable": likely, "inferred_edges": list(inferred_edges)}
