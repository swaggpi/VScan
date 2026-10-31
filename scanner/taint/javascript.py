"""JavaScript adapter for the taint pass (layer 1).

The SECOND language adapter behind the grammar-free core in
:mod:`scanner.taint.core` (after :mod:`scanner.taint.python`). It answers the
core's questions for JavaScript source: parsing (tree-sitter), Express/Koa
``request``-object source recognition, flow-sensitive intra-procedural
propagation, argument->parameter binding, call-site resolution and
dependency-symbol sink matching. All tree-sitter handling lives here; the core
knows nothing about it.

It re-parses the JavaScript source of the functions ON a proven reachability
path (``entrypoint -> handler -> ... -> dependency``) and checks whether a
*source* (an attacker-controlled read at the handler) propagates -- through
taint-preserving operations and proven argument/parameter bindings -- all the
way into the *sink* (the call into the dependency).

THE CARDINAL RULE (see :mod:`scanner.taint.core`)
-------------------------------------------------
Never assert a claim unless fully proven. A MISSED taint flow is acceptable; a
FALSE "tainted" claim is a CRITICAL failure. The default verdict is
``not_proven``. Every design choice below that resolves an ambiguity resolves it
in the direction that can only drop a real flow, never fabricate one.

Call-site resolution and symbol recognition are DELEGATED to the real JavaScript
analyzer (``JavaScriptAnalyzer._resolve_call`` / ``_build_symbol_table`` /
``_bound_names_at`` / ``_collect_functions``). The taint pass never hand-rolls a
dotted name or a scope: arg->param binding fires ONLY when the analyzer resolves
a call to ``("fn", <next_fn_id>)``, and a sink fires ONLY when it resolves a call
to ``("dep", dep_id, symbol)`` with ``symbol`` in the advisory's symbols. A
same-named call that the analyzer cannot positively resolve is never bound.

Request-object sources (Express/Koa)
-------------------------------------
The handler's FIRST positional parameter is the request object (Express
``(req, res, next)``; Koa ``(ctx, next)``). Member reads on it of ``query`` /
``body`` / ``params`` / ``headers`` / ``cookies`` (and ``.get(...)`` on those,
and Koa's ``ctx.request.body``) are tainted. Destructured forms
(``const {id} = req.query``, ``const {body} = req``) and param destructuring
(``({body}) => ...``) taint the bound source names. Request-object identity is
tracked through direct aliasing only (``const r = req``), as an env provenance
sentinel (:data:`_REQ`) that participates in the same MAY-join/kill algebra as
real taint -- so a conditional rebind of ``req`` keeps the request path (sound)
while an unconditional straight-line rebind kills it.

Deliberate conservative limitations (documented, not bugs)
----------------------------------------------------------
* Only Express/Koa first-parameter request sources are recognised. A handler
  with 4+ positional parameters is treated as a non-seedable error-middleware
  shape (``(err, req, res, next)``) and seeds NOTHING -- this can only miss a
  flow, never fabricate one.
* Return values of arbitrary function calls are NEVER treated as tainted (except
  a getter chained on a request source, mirroring the Python adapter's
  ``request.args.get(...)``). A flow laundered through a helper's return value is
  therefore MISSED -- including a cross-file helper that is NOT itself a node on
  the proven reachability path.
* Argument->parameter binding is declined for a call that spreads an argument
  (``helper(...xs)``), for a callee that declares a rest parameter
  (``function f(...args)``), for a default-valued parameter slot
  (``function f(a = 1)``), and for a call passing more positional arguments than
  the callee has bindable positional parameters.
* Taint is tracked for simple names only. Writing a tainted value into a
  member/subscript target (``obj.x = tainted``) does not taint ``obj``.
* Propagation is flow-sensitive with a proper MAY-dataflow JOIN at every merge
  (``if``/``else``, ``switch``, ``try``, ``for``/``while``/``do``). A reassignment
  to a non-tainted value KILLS a name on a straight-line path (last-write-wins);
  at a merge a name survives iff it survives on ANY incoming path; a loop body's
  0-iteration (entry) env is always retained, so a loop-body kill never removes
  taint. ``switch`` fall-through is NOT modelled (each case runs in isolation and
  the no-match path is retained unless a ``default`` is present) -- a sound
  over-approximation that can only keep or miss taint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..analyzers.javascript_analyzer import JavaScriptAnalyzer, _node_text
from ._support import _scan_support
from .core import (
    _Env,
    _assign_or_kill_names,
    _aug_bind_names,
    _copy_env,
    _join,
    _set_env,
    _split_fn_id,
)

# The Express/Koa request-object members that carry attacker-controlled data.
_REQUEST_SOURCE_ATTRS: frozenset[str] = frozenset(
    {"query", "body", "params", "headers", "cookies"}
)

# Members that KEEP request-object identity without being a source themselves,
# so a further source member resolves (Koa's ``ctx.request.body``).
_REQUEST_PASSTHROUGH: frozenset[str] = frozenset({"request"})

# Env provenance sentinel marking "this name holds the request object itself".
# It travels through the same join/kill algebra as a real source descriptor but
# is NEVER a taint by itself: a bare ``req`` is not attacker DATA, only
# ``req.body`` is. :func:`_real` strips it before any sink/bind decision.
_REQ: str = "@request"

# Node types that open a new function scope -- the flow walk never descends into
# these (a callback body / nested function is off-path; its calls do not fire
# and its return value is not tainted).
_FN_LITERAL_TYPES: frozenset[str] = frozenset(
    {
        "arrow_function",
        "function_expression",
        "generator_function",
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "class_declaration",
        "class",
    }
)


def _real(taint: set[str]) -> set[str]:
    """Strip the request-object sentinel: the attacker-DATA provenance only."""
    return taint - {_REQ}


# --------------------------------------------------------------------------
# Parsed-file cache
# --------------------------------------------------------------------------


@dataclass
class _JsFile:
    """Everything the pass needs about one re-parsed JavaScript source file."""

    root: Any  # tree-sitter root node (kept: call nodes are resolved against it)
    defs: dict[str, tuple[Any, Any]]  # qualname -> (fn_node, body_node)
    symtab: dict[str, dict[str, Any]]  # local name -> import/xmod descriptor
    local_functions: dict[str, str]  # top-level qualname -> fn_id
    analyzer: JavaScriptAnalyzer  # the per-repo analyzer (for _resolve_call)


class _FileCache:
    """Re-scans the repo once (for the dep graph + cross-file index), then
    lazily re-parses and caches the JavaScript files the pass touches.

    The analyzer's symbol table needs both a graph carrying the manifest's
    ``dep:npm:*`` nodes and the shared cross-file export index. Neither is handed
    to the adapter by the core, so the cache rebuilds them exactly as
    :func:`scanner.scan.scan_repo` does (walk -> dependencies -> repo index). The
    rebuilt graph is a throwaway used only to answer "does this package exist".
    """

    def __init__(self, repo_root: str) -> None:
        self._analyzer = JavaScriptAnalyzer()
        self._cache: dict[str, _JsFile | None] = {}
        self._graph, self._repo_index, self._source_cache = _scan_support(repo_root)

    def get(self, relpath: str) -> _JsFile | None:
        if relpath in self._cache:
            return self._cache[relpath]
        parsed = self._parse(relpath)
        self._cache[relpath] = parsed
        return parsed

    def _parse(self, relpath: str) -> _JsFile | None:
        source = self._source_cache.get(relpath)
        if source is None:
            return None
        try:
            root = self._analyzer._get_parser().parse(source.encode("utf-8")).root_node
        except Exception:  # pragma: no cover - parser never raises on bytes
            return None
        try:
            functions = self._analyzer._collect_functions(root)
            symtab = self._analyzer._build_symbol_table(
                root, f"mod:{relpath}", self._graph, relpath, self._repo_index
            )
        except Exception:  # pathological source: not analysable -> not_proven
            return None
        defs = {qual: (node, body) for qual, node, body in functions}
        local_functions = {
            qual: f"fn:{relpath}:{qual}" for qual, _n, _b in functions if "." not in qual
        }
        return _JsFile(
            root=root,
            defs=defs,
            symtab=symtab,
            local_functions=local_functions,
            analyzer=self._analyzer,
        )


# --------------------------------------------------------------------------
# Field / child helpers
# --------------------------------------------------------------------------


def _field(node: Any, name: str) -> Any:
    return node.child_by_field_name(name) if node is not None else None


def _named_children(node: Any) -> list[Any]:
    return [c for c in node.children if c.is_named] if node is not None else []


# --------------------------------------------------------------------------
# Assignment-target flattening (simple names only; member/subscript bind none)
# --------------------------------------------------------------------------


def _flatten_target(node: Any) -> list[str]:
    """Simple names bound by a target/pattern (over-approximating destructuring).

    A bare identifier yields itself. An object/array pattern yields every simple
    name it binds -- a SOUND over-approximation, since destructuring a tainted
    RHS could route the tainted element to any of them. A member/subscript target
    (``obj.x``) binds no simple name and yields nothing: a missed flow, never a
    false one, and what keeps ``obj.x = const`` from killing a plain ``obj``.
    """
    if node is None:
        return []
    t = node.type
    if t in ("identifier", "shorthand_property_identifier_pattern"):
        return [_node_text(node)]
    if t in (
        "object_pattern",
        "array_pattern",
        "rest_pattern",
        "assignment_pattern",
        "object_assignment_pattern",
    ):
        out: list[str] = []
        for child in node.children:
            out.extend(_flatten_target(child))
        return out
    if t == "pair_pattern":
        return _flatten_target(_field(node, "value"))
    return []


# --------------------------------------------------------------------------
# Taint-preserving expression evaluation
# --------------------------------------------------------------------------


def _taint_of_expr(node: Any, env: _Env) -> set[str]:
    """Provenance set of ``node`` under ``env``, via taint-preserving ops only.

    Returns the union of source descriptors that flow to the value of ``node``
    (the request-object sentinel :data:`_REQ` is only ever returned bare, for the
    request object itself; :func:`_real` drops it at decision points). An empty
    set means "not proven tainted". Only the enumerated operations preserve
    taint; every other construct -- crucially, an arbitrary call's return value
    -- yields the empty set.
    """
    if node is None:
        return set()
    t = node.type

    if t == "parenthesized_expression":
        return _taint_of_expr(_first_expr_child(node), env)

    if t == "identifier":
        return set(env.get(_node_text(node), set()))

    if t in (
        "number",
        "string",
        "true",
        "false",
        "null",
        "undefined",
        "regex",
        "this",
        "super",
    ):
        return set()

    if t == "member_expression":
        return _member_taint(node, env)

    if t == "subscript_expression":
        # Computed member ``x[i]``: base taint flows (member of tainted is
        # tainted); the request sentinel does NOT (a computed read of ``req`` is
        # not a recognised source -- skipped, a conservative miss).
        return _real(_taint_of_expr(_field(node, "object"), env))

    if t == "template_string":
        out: set[str] = set()
        for child in _named_children(node):
            if child.type == "template_substitution":
                out |= _real(_taint_of_expr(_first_expr_child(child), env))
        return out

    if t in ("binary_expression", "augmented_assignment_expression"):
        return _real(
            _taint_of_expr(_field(node, "left"), env)
            | _taint_of_expr(_field(node, "right"), env)
        )

    if t == "unary_expression":
        return _real(_taint_of_expr(_field(node, "argument"), env))

    if t == "ternary_expression":
        return _real(
            _taint_of_expr(_field(node, "consequence"), env)
            | _taint_of_expr(_field(node, "alternative"), env)
        )

    if t in ("array", "object"):
        out = set()
        for child in _named_children(node):
            out |= _real(_container_element_taint(child, env))
        return out

    if t == "spread_element":
        return _real(_taint_of_expr(_first_expr_child(node), env))

    if t == "await_expression":
        return _taint_of_expr(_first_expr_child(node), env)

    if t == "assignment_expression":
        # Value of ``x = v`` is v (the binding is applied by the statement pass).
        return _real(_taint_of_expr(_field(node, "right"), env))

    if t == "sequence_expression":
        exprs = _named_children(node)
        return _taint_of_expr(exprs[-1], env) if exprs else set()

    if t == "call_expression":
        return _call_result_taint(node, env)

    return set()


def _container_element_taint(child: Any, env: _Env) -> set[str]:
    """Taint of one array/object literal element (pair value / spread / elt)."""
    t = child.type
    if t == "pair":
        return _taint_of_expr(_field(child, "value"), env)
    if t == "spread_element":
        return _taint_of_expr(_first_expr_child(child), env)
    if t == "shorthand_property_identifier":
        # ``{ body }`` in an object literal is a load of the variable ``body``.
        return set(env.get(_node_text(child), set()))
    return _taint_of_expr(child, env)


def _member_taint(node: Any, env: _Env) -> set[str]:
    """Taint of ``obj.prop``: request source recognition + member-of-tainted."""
    obj = _field(node, "object")
    prop_node = _field(node, "property")
    obj_taint = _taint_of_expr(obj, env)
    out: set[str] = set()
    if _REQ in obj_taint and prop_node is not None:
        prop = _node_text(prop_node)
        if prop in _REQUEST_SOURCE_ATTRS:
            out.add(f"{_node_text(obj)}.{prop}")  # a real source
        elif prop in _REQUEST_PASSTHROUGH:
            out.add(_REQ)  # still the request object (Koa ctx.request)
    out |= _real(obj_taint)  # member of a tainted value stays tainted
    return out


def _call_result_taint(node: Any, env: _Env) -> set[str]:
    """Taint of a call's RESULT -- empty save a getter chained on a source.

    Mirrors the Python adapter's ``request.args.get(...)``: a method called on an
    already-recognised source (``req.query.get('x')``) yields that source. EVERY
    other call return is NOT proven tainted (the cardinal rule).
    """
    callee = _field(node, "function")
    if callee is not None and callee.type == "member_expression":
        inner = _real(_taint_of_expr(_field(callee, "object"), env))
        if inner:
            return inner
    return set()


def _first_expr_child(node: Any) -> Any:
    for child in _named_children(node):
        return child
    return None


# --------------------------------------------------------------------------
# Call-site walking (fires on_call in source order, never entering a callback)
# --------------------------------------------------------------------------


def _walk_calls(node: Any, env: _Env, on_call) -> None:
    """Fire ``on_call(call, env)`` for every call in ``node``, at this env.

    Does NOT descend into nested function literals (a callback / IIFE body is
    off-path: its calls must not fire here and its return value is not tainted).
    """
    if node is None or node.type in _FN_LITERAL_TYPES:
        return
    if node.type == "call_expression":
        on_call(node, env)
    for child in node.children:
        _walk_calls(child, env, on_call)


# --------------------------------------------------------------------------
# Binding: declarations / assignments / destructuring-from-request
# --------------------------------------------------------------------------


def _request_destructure(name_node: Any, base_text: str, env: _Env) -> None:
    """Bind an object pattern destructured from the request OBJECT itself.

    ``const {body, query} = req`` taints ``body``/``query`` as the corresponding
    request sources; a field that is not a recognised source is KILLED (it reads
    a non-source property of the request). Any non-object pattern kills all its
    names (destructuring the request object into an array is not a source).
    """
    if name_node is None or name_node.type != "object_pattern":
        _assign_or_kill_names(_flatten_target(name_node), set(), env)
        return
    for child in name_node.children:
        if child.type == "shorthand_property_identifier_pattern":
            _bind_request_field(_node_text(child), _node_text(child), base_text, env)
        elif child.type == "pair_pattern":
            key = _field(child, "key")
            val = _field(child, "value")
            if key is not None and val is not None:
                for local in _flatten_target(val):
                    _bind_request_field(_node_text(key), local, base_text, env)
        else:
            # ``{a = 1}`` default / ``{...rest}``: no recognised source.
            _assign_or_kill_names(_flatten_target(child), set(), env)


def _bind_request_field(key: str, local: str, base_text: str, env: _Env) -> None:
    if key in _REQUEST_SOURCE_ATTRS:
        env[local] = {f"{base_text}.{key}"}
    elif key in _REQUEST_PASSTHROUGH:
        env[local] = {_REQ}
    else:
        env.pop(local, None)


def _apply_binding(name_node: Any, value_node: Any, env: _Env) -> None:
    """Last-write-wins bind of ``name_node`` from ``value_node`` under ``env``."""
    value_taint = _taint_of_expr(value_node, env)
    if _REQ in value_taint and not _real(value_taint):
        # RHS is the request object itself: alias it, or destructure its sources.
        if name_node is not None and name_node.type == "identifier":
            env[_node_text(name_node)] = {_REQ}
        else:
            base = _node_text(value_node) if value_node is not None else "req"
            _request_destructure(name_node, base, env)
        return
    _assign_or_kill_names(_flatten_target(name_node), _real(value_taint), env)


# --------------------------------------------------------------------------
# Statement execution (flow-sensitive, with MAY-join at every merge)
# --------------------------------------------------------------------------


def _exec_block(block: Any, env: _Env, on_call) -> None:
    for stmt in _named_children(block):
        _exec_stmt(stmt, env, on_call)


def _exec_stmt_opt(stmt: Any, env: _Env, on_call) -> None:
    if stmt is not None:
        _exec_stmt(stmt, env, on_call)


def _exec_expression(expr: Any, env: _Env, on_call) -> None:
    """Apply one expression used as a statement (assignment kills, else calls)."""
    if expr is None:
        return
    t = expr.type
    if t == "assignment_expression":
        _walk_calls(_field(expr, "right"), env, on_call)
        _apply_binding(_field(expr, "left"), _field(expr, "right"), env)
        return
    if t == "augmented_assignment_expression":
        _walk_calls(_field(expr, "right"), env, on_call)
        rhs = _real(_taint_of_expr(_field(expr, "right"), env))
        _aug_bind_names(_flatten_target(_field(expr, "left")), rhs, env)
        return
    _walk_calls(expr, env, on_call)


def _apply_loop_body(
    body: Any,
    env: _Env,
    on_call,
    target: Any = None,
    iter_taint: set[str] | None = None,
) -> None:
    """Join a loop body (runs 0+ times) into ``env`` with a 2-pass fixpoint.

    The entry ``env`` is the 0-iteration path and is retained in every join, so a
    kill inside the body never removes a name. The loop target is (re)bound at the
    top of each pass -- tainted iff the iterable is -- so a non-tainted loop
    variable shadowing an attacker name is not seen tainted inside the body.
    """
    for _ in range(2):
        body_env = _copy_env(env)
        if target is not None:
            _assign_or_kill_names(_flatten_target(target), iter_taint or set(), body_env)
        _exec_stmt_opt(body, body_env, on_call)
        _set_env(env, _join(env, body_env))


def _exec_stmt(stmt: Any, env: _Env, on_call) -> None:
    """Apply one statement to ``env`` in order (see module docstring for rules)."""
    if stmt is None:
        return
    t = stmt.type

    # Nested scopes bind their own names; never descend into them.
    if t in _FN_LITERAL_TYPES:
        return

    if t in ("statement_block", "else_clause", "labeled_statement"):
        _exec_block(stmt, env, on_call)
        return

    if t in ("lexical_declaration", "variable_declaration"):
        for decl in stmt.children:
            if decl.type != "variable_declarator":
                continue
            value = _field(decl, "value")
            _walk_calls(value, env, on_call)
            _apply_binding(_field(decl, "name"), value, env)
        return

    if t == "expression_statement":
        for child in _named_children(stmt):
            _exec_expression(child, env, on_call)
        return

    if t == "if_statement":
        _walk_calls(_field(stmt, "condition"), env, on_call)
        body_env = _copy_env(env)
        _exec_stmt_opt(_field(stmt, "consequence"), body_env, on_call)
        else_env = _copy_env(env)
        _exec_stmt_opt(_field(stmt, "alternative"), else_env, on_call)
        _set_env(env, _join(body_env, else_env))
        return

    if t == "for_in_statement":
        right = _field(stmt, "right")
        _walk_calls(right, env, on_call)
        iter_taint = _real(_taint_of_expr(right, env))
        _apply_loop_body(
            _field(stmt, "body"), env, on_call, _field(stmt, "left"), iter_taint
        )
        return

    if t == "for_statement":
        _exec_stmt_opt(_field(stmt, "initializer"), env, on_call)
        _walk_calls(_field(stmt, "condition"), env, on_call)
        increment = _field(stmt, "increment")
        for _ in range(2):
            body_env = _copy_env(env)
            _exec_stmt_opt(_field(stmt, "body"), body_env, on_call)
            _exec_expression(increment, body_env, on_call)
            _set_env(env, _join(env, body_env))
        return

    if t == "while_statement":
        _walk_calls(_field(stmt, "condition"), env, on_call)
        _apply_loop_body(_field(stmt, "body"), env, on_call)
        return

    if t == "do_statement":
        # Body runs at least once, but modelled as a loop (entry env retained)
        # so a body kill cannot drop taint -- sound in the existential direction.
        _apply_loop_body(_field(stmt, "body"), env, on_call)
        _walk_calls(_field(stmt, "condition"), env, on_call)
        return

    if t == "try_statement":
        try_env = _copy_env(env)
        _exec_stmt_opt(_field(stmt, "body"), try_env, on_call)
        exit_envs: list[_Env] = [try_env]
        handler = _field(stmt, "handler")
        if handler is not None:
            handler_env = _copy_env(env)  # entry: the body may not have completed
            _assign_or_kill_names(
                _flatten_target(_field(handler, "parameter")), set(), handler_env
            )
            _exec_stmt_opt(_field(handler, "body"), handler_env, on_call)
            exit_envs.append(handler_env)
        _set_env(env, _join(*exit_envs))
        finalizer = _field(stmt, "finalizer")
        if finalizer is not None:  # ``finally`` always runs -> straight-line
            _exec_stmt_opt(_field(finalizer, "body"), env, on_call)
        return

    if t == "switch_statement":
        _walk_calls(_field(stmt, "value"), env, on_call)
        body = _field(stmt, "body")
        case_envs: list[_Env] = []
        has_default = False
        for case in _named_children(body):
            if case.type not in ("switch_case", "switch_default"):
                continue
            if case.type == "switch_default":
                has_default = True
            case_env = _copy_env(env)
            value_node = _field(case, "value")
            for child in _named_children(case):
                if child is value_node:
                    continue  # the case label, not a body statement
                _exec_stmt(child, case_env, on_call)
            case_envs.append(case_env)
        if not has_default:
            case_envs.append(_copy_env(env))  # the no-match fall-through path
        if case_envs:
            _set_env(env, _join(*case_envs))
        return

    if t == "with_statement":
        # The body always executes -> straight-line (kills apply).
        _walk_calls(_field(stmt, "object"), env, on_call)
        _exec_stmt_opt(_field(stmt, "body"), env, on_call)
        return

    # Any other statement (return / throw / break / continue / empty / ...):
    # fire whatever calls it contains.
    _walk_calls(stmt, env, on_call)


def _run_flow(fnode: Any, env: _Env, on_call) -> _Env:
    """Flow-sensitive walk of ``fnode``'s body; mutate and return ``env``.

    Handles both block-bodied functions and expression-bodied arrows
    (``(req) => sink(req.body)``), firing ``on_call`` at each call's position.
    """
    body = _field(fnode, "body")
    if body is None:
        return env
    if body.type == "statement_block":
        _exec_block(body, env, on_call)
    else:
        _walk_calls(body, env, on_call)  # concise arrow body
    return env


# --------------------------------------------------------------------------
# Parameters (ordered positional slots) + argument binding
# --------------------------------------------------------------------------


@dataclass
class _ParamSlot:
    names: list[str]  # the simple names this positional param binds
    bindable: bool  # False for a default-valued param (never bound)


def _positional_param_slots(fnode: Any) -> tuple[list[_ParamSlot], bool]:
    """Ordered positional parameter slots and whether a rest (``...args``) exists.

    The analyzer exposes bound-name SETS only; the taint pass needs ORDER to map
    positional arguments. A destructuring-pattern param is one slot binding ALL
    the names its pattern binds. A default-valued param (``a = 1``) is a
    non-bindable slot (occupies a position but is never bound -- conservative). A
    rest parameter sets the ``has_rest`` flag (binding is then declined).
    """
    params = _field(fnode, "parameters")
    if params is None:
        single = _field(fnode, "parameter")  # ``x => ...``
        if single is not None and single.type == "identifier":
            return [_ParamSlot([_node_text(single)], True)], False
        return [], False

    slots: list[_ParamSlot] = []
    has_rest = False
    for child in _named_children(params):
        t = child.type
        if t == "identifier":
            slots.append(_ParamSlot([_node_text(child)], True))
        elif t in ("object_pattern", "array_pattern"):
            slots.append(_ParamSlot(_flatten_target(child), True))
        elif t == "rest_pattern":
            has_rest = True
        elif t in ("assignment_pattern", "object_assignment_pattern"):
            slots.append(_ParamSlot([], False))  # default param: not bound
        else:
            slots.append(_ParamSlot([], False))
    return slots, has_rest


def _call_arguments(call: Any) -> list[Any]:
    return _named_children(_field(call, "arguments"))


def _call_has_spread(args: list[Any]) -> bool:
    return any(arg.type == "spread_element" for arg in args)


def _bind_call_args(call: Any, next_fnode: Any, env: _Env, seed: _Env) -> None:
    """Bind tainted arguments of ``call`` to ``next_fnode``'s parameters.

    ``env`` is the taint state at the call's position; ``seed`` is the callee's
    env, updated in place (union). Binding is declined for a spread argument, a
    callee rest parameter, or more positional arguments than bindable positional
    parameters (conservative: a missed flow, never a guessed one).
    """
    args = _call_arguments(call)
    if _call_has_spread(args):
        return
    slots, has_rest = _positional_param_slots(next_fnode)
    if has_rest or len(args) > len(slots):
        return
    for index, arg in enumerate(args):
        slot = slots[index]
        if not slot.bindable:
            continue
        taint = _real(_taint_of_expr(arg, env))
        if taint:
            for name in slot.names:
                seed.setdefault(name, set()).update(taint)


# --------------------------------------------------------------------------
# Source seeding
# --------------------------------------------------------------------------


def _first_param_node(fnode: Any) -> tuple[Any, int]:
    """Return ``(first_positional_param_node, positional_count)``.

    The node is the request-object parameter; the count drives the conservative
    error-middleware guard. ``(None, count)`` when there is no positional param.
    """
    params = _field(fnode, "parameters")
    if params is None:
        single = _field(fnode, "parameter")
        if single is not None:
            return single, 1
        return None, 0
    positional = [
        c for c in _named_children(params) if c.type != "rest_pattern"
    ]
    first = positional[0] if positional else None
    return first, len(positional)


def _handler_seed(fnode: Any) -> _Env:
    """Seed the request-object sources from a route handler's first parameter.

    Express ``(req, res, next)`` / Koa ``(ctx, next)``: the first positional
    parameter is the request object. A handler with 4+ positional parameters is
    treated as a non-seedable error-middleware shape and seeds nothing (a
    conservative miss, never a false source).
    """
    env: _Env = {}
    first, count = _first_param_node(fnode)
    if first is None or count >= 4:
        return env
    t = first.type
    if t == "identifier":
        env[_node_text(first)] = {_REQ}
    elif t == "object_pattern":
        _request_destructure(first, "req", env)
    elif t == "assignment_pattern":  # ``(req = {}) => ...``
        left = _field(first, "left")
        if left is not None and left.type == "identifier":
            env[_node_text(left)] = {_REQ}
    return env


# --------------------------------------------------------------------------
# Per-hop analysis (bind into next) + sink detection
# --------------------------------------------------------------------------


def _resolve(file_info: _JsFile, call: Any) -> tuple[str, ...]:
    """Resolve a call via the real analyzer (bound-names computed per call site)."""
    analyzer = file_info.analyzer
    bound = analyzer._bound_names_at(call)
    return analyzer._resolve_call(call, file_info.symtab, bound, file_info.local_functions)


# --------------------------------------------------------------------------
# FnInfo + the adapter
# --------------------------------------------------------------------------


@dataclass
class _FnInfo:
    """Opaque per-function info handed back to the driver (see the Protocol)."""

    file: _JsFile
    node: Any
    body: Any
    qual: str
    relpath: str
    fn_id: str


class JavaScriptTaintAdapter:
    """:class:`scanner.taint.core.TaintAdapter` for JavaScript source.

    ``cache`` is a :class:`_FileCache`; ``*_info`` objects are :class:`_FnInfo`.
    """

    def language_matches(self, relpath: str) -> bool:
        return relpath.endswith((".js", ".mjs", ".cjs", ".jsx"))

    def make_cache(self, repo_root: str) -> _FileCache:
        return _FileCache(repo_root)

    def resolve_function(self, cache: _FileCache, fn_id: str) -> _FnInfo | None:
        split = _split_fn_id(fn_id)
        if split is None:
            return None
        relpath, qual = split
        parsed = cache.get(relpath)
        if parsed is None:
            return None
        entry = parsed.defs.get(qual)
        if entry is None:
            return None
        node, body = entry
        return _FnInfo(
            file=parsed, node=node, body=body, qual=qual, relpath=relpath, fn_id=fn_id
        )

    def handler_seed(self, fn_info: _FnInfo) -> _Env:
        return _handler_seed(fn_info.node)

    def bind_into_next(
        self, caller_info: _FnInfo, env: _Env, next_info: _FnInfo
    ) -> _Env:
        seed: _Env = {}

        def on_call(call: Any, call_env: _Env) -> None:
            result = _resolve(caller_info.file, call)
            if result[0] == "fn" and result[1] == next_info.fn_id:
                _bind_call_args(call, next_info.node, call_env, seed)

        _run_flow(caller_info.node, env, on_call)
        return seed

    def detect_sink(
        self,
        sink_info: _FnInfo,
        env: _Env,
        dep_symbols: set[str],
        dep_id: str,  # noqa: ARG002 - part of the seam; the JS gate is unchanged
    ) -> tuple[str, str] | None:
        found: list[tuple[str, str]] = []

        def on_call(call: Any, call_env: _Env) -> None:
            if found:
                return
            result = _resolve(sink_info.file, call)
            if result[0] != "dep" or result[2] not in dep_symbols:
                return
            for arg in _call_arguments(call):
                if arg.type == "spread_element":
                    continue
                taint = _real(_taint_of_expr(arg, call_env))
                if taint:
                    found.append((result[2], sorted(taint)[0]))
                    return

        _run_flow(sink_info.node, env, on_call)
        return found[0] if found else None
