"""Go adapter for the taint pass (layer 1).

The THIRD language adapter behind the grammar-free core in
:mod:`scanner.taint.core` (after :mod:`scanner.taint.python` and
:mod:`scanner.taint.javascript`). It answers the core's questions for Go source:
parsing (tree-sitter), ``net/http`` / gin / echo / chi / gorilla-mux
request-object source recognition, flow-sensitive intra-procedural propagation,
argument->parameter binding, call-site resolution and dependency-symbol sink
matching. All tree-sitter handling lives here; the core knows nothing about it.

It re-parses the Go source of the functions ON a proven reachability path
(``entrypoint -> handler -> ... -> dependency``) and checks whether a *source*
(an attacker-controlled read at the handler) propagates -- through
taint-preserving operations and proven argument/parameter bindings -- all the
way into the *sink* (the call into the dependency).

THE CARDINAL RULE (see :mod:`scanner.taint.core`)
-------------------------------------------------
Never assert a claim unless fully proven. A MISSED taint flow is acceptable; a
FALSE "tainted" claim is a CRITICAL failure. The default verdict is
``not_proven``. Every design choice below that resolves an ambiguity resolves it
in the direction that can only drop a real flow, never fabricate one.

Call-site resolution and symbol recognition are DELEGATED to the real Go
analyzer (``GoAnalyzer._resolve_call`` / ``_process_imports`` / ``_bound_names``
/ ``_collect_functions`` / ``_go_dep_index``). The taint pass never hand-rolls a
dotted name or a scope: arg->param binding fires ONLY when the analyzer resolves
a call to ``("fn", <next_fn_id>)``, and a sink fires ONLY when it resolves a call
to ``("dep", dep_id, symbol)`` with ``symbol`` in the advisory's symbols. A
same-named call that the analyzer cannot positively resolve is never bound.

Request-object sources (net/http + gin + echo + chi + gorilla/mux)
------------------------------------------------------------------
The request/context object is identified BY TYPE at the handler's parameters
(reusing the parameter type text). A ``*http.Request`` parameter, a
``*gin.Context``, or an ``echo.Context`` seeds an env provenance SENTINEL
(:data:`_REQ` / :data:`_CTX_GIN` / :data:`_CTX_ECHO`) that travels through the
same MAY-join/kill algebra as real taint but is NEVER attacker DATA by itself
(:func:`_real` strips it before any sink/bind decision). A recognised source
READ or CALL on such an object yields a real source descriptor:

* ``*http.Request r``: ``r.FormValue``/``r.PostFormValue``/``r.Referer``/
  ``r.UserAgent``/``r.Cookie`` (calls); ``r.Form``/``r.PostForm``/``r.Header``/
  ``r.Body`` (fields); ``r.URL.Query()`` (and ``.Get``/``.Encode`` on its
  result); ``r.Header.Get(...)``; ``r.Form[...]``/``r.Form.Get(...)``; the body
  readers ``io.ReadAll(r.Body)`` / ``ioutil.ReadAll(r.Body)``; and
  ``json.NewDecoder(r.Body).Decode(&x)`` (taints ``x``).
* gorilla/mux: ``mux.Vars(r)`` (map; indexing tainted).
* ``*gin.Context c``: ``c.Query``/``c.PostForm``/``c.Param``/``c.GetHeader``
  (calls); ``c.Request`` (then net/http rules); ``c.ShouldBindJSON(&x)`` /
  ``c.BindJSON(&x)`` (taint ``x``).
* ``echo.Context c``: ``c.QueryParam``/``c.FormValue``/``c.Param`` (calls);
  ``c.Bind(&x)`` (taints ``x``).

Request/context identity is tracked through parameters (by type) and direct
aliasing only (``r2 := r``, ``u := r.URL``, ``rr := c.Request``).

Taint-preserving expression rules (handled; everything else drops taint)
------------------------------------------------------------------------
identifier load; selector/index of a tainted value (``x.F``, ``x[i]``,
``m[k]``); string ``+`` / binary; ``fmt.Sprintf``/``Sprint``/``Sprintln`` with a
tainted arg; slice ``x[a:b]``; type assertions / conversions (``T(x)`` /
``x.(T)`` / ``[]byte(x)``) transparent; ``&x`` / ``*x`` transparent;
``append(dst, tainted)`` -> tainted; composite literals containing a tainted
element; ``range`` over a tainted collection taints the VALUE (2-var form only;
the key/index is left untainted -- sound, since map-vs-slice is not proven).
Short var decl ``:=``, ``var``, assignment ``=``, ``+=``.

MULTI-RETURN / tuple assignment: for a single RHS bound to several targets
(``data, err := io.ReadAll(r.Body)``; ``v, ok := m[k]`` / ``x.(T)`` / ``<-ch``),
only the DATA position (index 0) is ever tainted; the 2nd+ targets (``err`` /
the comma-ok presence bool) are killed -- they are never attacker data.

Deliberate conservative limitations (documented, not bugs)
----------------------------------------------------------
* Generic function-call RETURN values are NEVER tainted (only the enumerated
  request sources, conversions, ``append``, ``Sprintf`` family, body readers and
  getters chained on an already-tainted receiver are). A flow laundered through
  a helper's return value is MISSED.
* Argument->parameter binding is declined for a spread argument (``f(xs...)``),
  for a callee with a variadic parameter (``func f(xs ...T)``), for an unnamed
  typed parameter slot, and for a call passing more positional arguments than
  bindable positional parameters.
* Taint is tracked for simple names only: ``s.F = tainted`` does not taint ``s``.
* Propagation is flow-sensitive with a MAY-dataflow JOIN at every merge
  (``if``/``else``, ``for``, ``switch``, ``type switch``, ``select``). A
  reassignment to a non-tainted value KILLS on a straight-line path; at a merge a
  name survives iff it survives on ANY path; a loop body's 0-iteration (entry)
  env is always retained, so a loop-body kill never removes taint. Statement
  initializers (``if x := f(); ...``) and ``range``/type-switch variables are
  scoped to their construct and dropped afterwards.
* Function literals, goroutines (``go f()``), deferred calls (``defer f()``),
  channel sends/receives and struct-field writes never carry or fire taint.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from tree_sitter_language_pack import get_parser

from ..analyzers.go_analyzer import GoAnalyzer
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

# --------------------------------------------------------------------------
# Env provenance sentinels (request/context identity -- never attacker DATA)
# --------------------------------------------------------------------------

_REQ: str = "@req"  # a value whose type is ``*http.Request``
_CTX_GIN: str = "@ctx:gin"  # a value whose type is ``*gin.Context``
_CTX_ECHO: str = "@ctx:echo"  # a value whose type is ``echo.Context``
_URL: str = "@req.url"  # ``r.URL`` (only ``.Query()`` on it is a source)
_DECODER: str = "@decoder"  # ``json.NewDecoder(<tainted body>)`` result

_SENTINELS: frozenset[str] = frozenset({_REQ, _CTX_GIN, _CTX_ECHO, _URL, _DECODER})

# net/http ``*http.Request`` recognised sources.
_HTTP_SOURCE_METHODS: frozenset[str] = frozenset(
    {"FormValue", "PostFormValue", "Referer", "UserAgent"}
)
# Fields of ``*http.Request`` that ARE attacker data (url.Values / http.Header /
# the body stream): indexing / ``.Get`` / a body reader keeps the taint.
_HTTP_SOURCE_FIELDS: frozenset[str] = frozenset({"Form", "PostForm", "Header", "Body"})

# gin ``*gin.Context`` sources and binds.
_GIN_SOURCE_METHODS: frozenset[str] = frozenset(
    {"Query", "PostForm", "Param", "GetHeader"}
)
_GIN_BIND_METHODS: frozenset[str] = frozenset({"ShouldBindJSON", "BindJSON"})

# echo ``echo.Context`` sources and binds.
_ECHO_SOURCE_METHODS: frozenset[str] = frozenset({"QueryParam", "FormValue", "Param"})
_ECHO_BIND_METHODS: frozenset[str] = frozenset({"Bind"})

# Taint-preserving formatting helpers (modelled like Python's ``str.format``).
_SPRINTF: frozenset[str] = frozenset({"Sprintf", "Sprint", "Sprintln"})

# Body readers whose returned bytes carry the taint of their argument.
_READALL_PKGS: frozenset[str] = frozenset({"io", "ioutil"})

# Getter methods that keep the taint of an already-tainted receiver
# (``r.URL.Query().Get(...)`` / ``r.Header.Get(...)`` / ``vals.Encode()``).
_GETTERS_ON_TAINT: frozenset[str] = frozenset({"Get", "Encode"})

# Predeclared type names usable as a conversion ``T(x)`` (transparent).
_CONV_BUILTINS: frozenset[str] = frozenset(
    {
        "string", "bool", "byte", "rune", "error", "any", "uintptr",
        "int", "int8", "int16", "int32", "int64",
        "uint", "uint8", "uint16", "uint32", "uint64",
        "float32", "float64", "complex64", "complex128",
    }
)

# Literal node types (never tainted).
_LITERALS: frozenset[str] = frozenset(
    {
        "int_literal", "float_literal", "imaginary_literal", "rune_literal",
        "interpreted_string_literal", "raw_string_literal", "true", "false",
        "nil", "iota",
    }
)

# Subtrees the flow walk never descends into (off-path bodies / deferred calls).
_SKIP_SUBTREES: frozenset[str] = frozenset(
    {"func_literal", "go_statement", "defer_statement", "send_statement"}
)


def _real(taint: set[str]) -> set[str]:
    """Strip the identity sentinels: the attacker-DATA provenance only."""
    return taint - _SENTINELS


# --------------------------------------------------------------------------
# Node / field helpers
# --------------------------------------------------------------------------


def _field(node: Any, name: str) -> Any:
    return node.child_by_field_name(name) if node is not None else None


def _named_children(node: Any) -> list[Any]:
    return [c for c in node.children if c.is_named] if node is not None else []


def _txt(node: Any) -> str:
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8")
    except Exception:  # pragma: no cover - text is bytes on real trees
        return ""


def _first_expr_child(node: Any) -> Any:
    for child in _named_children(node):
        return child
    return None


def _target_name(node: Any) -> str | None:
    """Simple name bound by an assignment target, or ``None``.

    A bare identifier yields itself (except the blank ``_``). A selector/index
    target (``s.F``, ``m[k]``) binds no simple name -> ``None``: a missed flow,
    never a false one, and what keeps ``s.F = const`` from killing a plain ``s``.
    """
    if node is None:
        return None
    if node.type == "identifier":
        name = _txt(node)
        return name if name and name != "_" else None
    return None


def _addr_target_name(arg: Any) -> str | None:
    """Simple name a bind call writes through: ``&x`` / ``*x`` / ``x`` -> ``x``."""
    if arg is None:
        return None
    if arg.type == "unary_expression":
        return _target_name(_field(arg, "operand"))
    return _target_name(arg)


def _seed_sentinel_for_type(type_text: str) -> str | None:
    """Map a parameter's type text to its request/context sentinel, or ``None``.

    Matches by the qualified type suffix after stripping a leading pointer
    (``*http.Request`` -> ``http.Request``). An aliased framework import is not
    recognised (a conservative miss, never a false source).
    """
    t = type_text.strip().lstrip("*").strip()
    if t.endswith("http.Request"):
        return _REQ
    if t.endswith("gin.Context"):
        return _CTX_GIN
    if t.endswith("echo.Context"):
        return _CTX_ECHO
    return None


# --------------------------------------------------------------------------
# Taint-preserving expression evaluation
# --------------------------------------------------------------------------


def _taint_of_expr(node: Any, env: _Env) -> set[str]:
    """Provenance set of ``node`` under ``env``, via taint-preserving ops only.

    An identifier load returns its env set verbatim (sentinels included, so a
    direct alias can carry request identity); every other construct strips
    sentinels with :func:`_real` and only propagates the enumerated
    taint-preserving operations. An empty set means "not proven tainted".
    """
    if node is None:
        return set()
    t = node.type

    if t == "parenthesized_expression":
        return _taint_of_expr(_first_expr_child(node), env)

    if t == "identifier":
        return set(env.get(_txt(node), set()))

    if t in _LITERALS:
        return set()

    if t == "selector_expression":
        return _selector_taint(node, env)

    if t == "index_expression":
        # ``x[i]`` / ``m[k]``: member of a tainted value stays tainted.
        return _real(_taint_of_expr(_field(node, "operand"), env))

    if t == "slice_expression":
        return _real(_taint_of_expr(_field(node, "operand"), env))

    if t == "type_assertion_expression":
        return _real(_taint_of_expr(_field(node, "operand"), env))

    if t == "type_conversion_expression":
        return _real(_taint_of_expr(_field(node, "operand"), env))

    if t == "unary_expression":
        # ``&x`` / ``*x`` / ``!x`` / ``-x``: transparent (address-of / deref / ...)
        return _real(_taint_of_expr(_field(node, "operand"), env))

    if t == "binary_expression":
        return _real(
            _taint_of_expr(_field(node, "left"), env)
            | _taint_of_expr(_field(node, "right"), env)
        )

    if t == "call_expression":
        return _call_taint(node, env)

    if t == "composite_literal":
        return _composite_taint(node, env)

    return set()


def _selector_taint(node: Any, env: _Env) -> set[str]:
    """Taint of ``obj.field``: request source recognition + member-of-tainted."""
    operand = _field(node, "operand")
    field = _txt(_field(node, "field"))
    obj = _taint_of_expr(operand, env)
    out: set[str] = set()
    if _CTX_GIN in obj:
        if field == "Request":
            out.add(_REQ)  # gin ctx.Request IS the net/http request
    elif _REQ in obj:
        if field in _HTTP_SOURCE_FIELDS:
            out.add(f"{_txt(operand)}.{field}")  # url.Values / http.Header / body
        elif field == "URL":
            out.add(_URL)  # only ``.Query()`` on it is a source
    out |= _real(obj)  # member of a tainted value stays tainted
    return out


def _composite_taint(node: Any, env: _Env) -> set[str]:
    """Taint of a composite literal: any tainted element taints the whole."""
    body = _field(node, "body")
    out: set[str] = set()
    for child in _named_children(body):
        if child.type == "keyed_element":
            out |= _real(_taint_of_expr(_field(child, "value"), env))
        elif child.type == "literal_element":
            out |= _real(_taint_of_expr(_first_expr_child(child), env))
        else:
            out |= _real(_taint_of_expr(child, env))
    return out


def _call_taint(node: Any, env: _Env) -> set[str]:
    """Taint of a call's RESULT -- empty save the enumerated whitelist."""
    callee = _field(node, "function")
    if callee is None:
        return set()
    args = _call_args(node)

    if callee.type == "identifier":
        name = _txt(callee)
        if name == "append" or name in _CONV_BUILTINS:
            # ``append(dst, tainted)`` / ``string(tainted)``: transparent.
            out: set[str] = set()
            for arg in args:
                out |= _real(_taint_of_expr(arg, env))
            return out
        # Any other bare function call return is NOT proven tainted.
        return set()

    if callee.type == "selector_expression":
        operand = _field(callee, "operand")
        field = _txt(_field(callee, "field"))
        op_text = _txt(operand)
        op_is_id = operand is not None and operand.type == "identifier"

        if field in _SPRINTF and op_is_id and op_text == "fmt":
            out = set()
            for arg in args:
                out |= _real(_taint_of_expr(arg, env))
            return out

        if field == "ReadAll" and op_is_id and op_text in _READALL_PKGS:
            out = set()
            for arg in args:
                out |= _taint_of_expr(arg, env)  # r.Body is a real source
            return _real(out)

        if field == "NewDecoder":
            inner: set[str] = set()
            for arg in args:
                inner |= _taint_of_expr(arg, env)
            return {_DECODER} if _real(inner) else set()

        obj = _taint_of_expr(operand, env)
        if _CTX_GIN in obj and field in _GIN_SOURCE_METHODS:
            return {f"{op_text}.{field}"}
        if _CTX_ECHO in obj and field in _ECHO_SOURCE_METHODS:
            return {f"{op_text}.{field}"}
        if _REQ in obj and (field in _HTTP_SOURCE_METHODS or field == "Cookie"):
            return {f"{op_text}.{field}"}
        if _URL in obj and field == "Query":
            return {f"{op_text}.Query"}
        if field == "Vars" and args and _REQ in _taint_of_expr(args[0], env):
            return {f"{op_text}.Vars"}  # gorilla/mux.Vars(r)
        if field in _GETTERS_ON_TAINT and _real(obj):
            return _real(obj)  # getter chained on a tainted receiver

    return set()


# --------------------------------------------------------------------------
# Bind-call effects (ShouldBindJSON / Bind / Decoder.Decode taint a target)
# --------------------------------------------------------------------------


def _apply_bind_call(call: Any, env: _Env) -> None:
    """If ``call`` is a decode/bind call, taint the pointed-to target variable.

    Covers ``c.ShouldBindJSON(&x)`` / ``c.BindJSON(&x)`` (gin), ``c.Bind(&x)``
    (echo) and ``json.NewDecoder(r.Body).Decode(&x)`` (or a tainted-decoder
    variable). The taint lands on the address-of argument's simple name.
    """
    callee = _field(call, "function")
    if callee is None or callee.type != "selector_expression":
        return
    operand = _field(callee, "operand")
    field = _txt(_field(callee, "field"))
    obj = _taint_of_expr(operand, env)
    desc: str | None = None
    if _CTX_GIN in obj and field in _GIN_BIND_METHODS:
        desc = f"{_txt(operand)}.{field}"
    elif _CTX_ECHO in obj and field in _ECHO_BIND_METHODS:
        desc = f"{_txt(operand)}.{field}"
    elif field == "Decode" and _DECODER in obj:
        desc = f"{_txt(operand)}.Decode"
    if desc is None:
        return
    for arg in _call_args(call):
        name = _addr_target_name(arg)
        if name:
            env[name] = {desc}
            return


# --------------------------------------------------------------------------
# Call-site walking (fires on_call in source order, never entering a callback)
# --------------------------------------------------------------------------


def _walk_calls(node: Any, env: _Env, on_call) -> None:
    """Fire ``on_call(call, env)`` for every call in ``node``, at this env.

    Applies decode/bind-call effects to ``env`` at each call's position so a
    later statement (and the sink) sees the bound target tainted. Never descends
    into a function literal, goroutine, deferred call or channel send.
    """
    if node is None or node.type in _SKIP_SUBTREES:
        return
    if node.type == "call_expression":
        _apply_bind_call(node, env)
        on_call(node, env)
    for child in node.children:
        _walk_calls(child, env, on_call)


# --------------------------------------------------------------------------
# Binding: short var decl / assignment / var spec (last-write-wins + tuple)
# --------------------------------------------------------------------------


def _bind_one(target: Any, value: Any, env: _Env) -> None:
    """Last-write-wins bind of a single ``target`` from ``value`` under ``env``."""
    name = _target_name(target)
    if name is None:
        return  # member/index target binds nothing and kills nothing
    vt = _taint_of_expr(value, env)
    real = _real(vt)
    if (
        not real
        and (vt & _SENTINELS)
        and value is not None
        and value.type in ("identifier", "selector_expression", "parenthesized_expression")
    ):
        # Direct alias of a request/context identity (``r2 := r``, ``u := r.URL``).
        env[name] = set(vt & _SENTINELS)
        return
    # Plain simple-name set-or-kill: the shared core primitive (python.py and
    # javascript.py route through the same helper). The sentinel-aliasing above
    # is the only grammar-specific extension.
    _assign_or_kill_names([name], real, env)


def _bind_tuple(targets: list[Any], rhs: Any, env: _Env) -> None:
    """Bind N targets from a single RHS (``a, b := f()``), precisely.

    Only the DATA position (index 0) may ever carry taint; every later target is
    killed. This covers both shapes soundly:

    * a WHITELISTED source CALL (``data, err := io.ReadAll(r.Body)``): index 0 is
      the bytes, the rest is ``err``;
    * a comma-ok / 2-value expression (``v, ok := m[k]`` / ``x.(T)`` / ``<-ch``):
      index 0 is the value, index 1+ is the presence bool or error.

    The 2nd (and later) targets are NEVER attacker data, so tainting them was a
    FALSE ``tainted`` (the comma-ok over-taint bug). A genuine multi-value
    expression that is none of these is vanishingly rare; the index-0-only choice
    stays conservative (it can only drop a real flow, never fabricate one). The
    per-target set-or-kill routes through the shared core primitive; the index-0
    rule is the only grammar-specific part.
    """
    real = _real(_taint_of_expr(rhs, env))
    for index, target in enumerate(targets):
        name = _target_name(target)
        if name is None:
            continue  # member/index target binds nothing and kills nothing
        _assign_or_kill_names([name], real if index == 0 else set(), env)


def _apply_multi(targets: list[Any], rexprs: list[Any], env: _Env) -> None:
    """Pair assignment targets with RHS expressions (with a tuple fallback)."""
    if len(rexprs) == len(targets):
        for target, value in zip(targets, rexprs, strict=False):
            _bind_one(target, value, env)
    elif len(rexprs) == 1 and targets:
        _bind_tuple(targets, rexprs[0], env)
    else:
        for target in targets:
            name = _target_name(target)
            if name:
                env.pop(name, None)


def _declared_names(stmt: Any) -> list[str]:
    """Names a short var declaration introduces (for scoping an if/for init)."""
    if stmt is not None and stmt.type == "short_var_declaration":
        left = _field(stmt, "left")
        return [n for n in (_target_name(t) for t in _named_children(left)) if n]
    return []


# --------------------------------------------------------------------------
# Statement execution (flow-sensitive, with MAY-join at every merge)
# --------------------------------------------------------------------------


def _exec_block(block: Any, env: _Env, on_call) -> None:
    for child in _named_children(block):
        if child.type == "statement_list":
            for stmt in _named_children(child):
                _exec_stmt(stmt, env, on_call)
        else:
            _exec_stmt(child, env, on_call)


def _exec_case_body(case: Any, env: _Env, on_call, skip: Any = None) -> None:
    """Run the statements of a switch/select case (they sit in a statement_list)."""
    for child in _named_children(case):
        if child is skip:
            continue
        if child.type == "statement_list":
            for stmt in _named_children(child):
                _exec_stmt(stmt, env, on_call)
        elif child.type in ("expression_list", "type_identifier") or child.type.endswith(
            "_type"
        ):
            continue  # the case label / asserted type, not a body statement
        else:
            _exec_stmt(child, env, on_call)


def _exec_assign(stmt: Any, env: _Env, on_call, *, decl: bool) -> None:
    left = _field(stmt, "left")
    right = _field(stmt, "right")
    _walk_calls(right, env, on_call)
    targets = _named_children(left)
    rexprs = _named_children(right)
    operator = _txt(_field(stmt, "operator"))
    if not decl and operator not in ("", "=", ":="):
        # Augmented assignment ``x += y`` (reads the old value; never kills).
        rhs: set[str] = set()
        for expr in rexprs:
            rhs |= _real(_taint_of_expr(expr, env))
        names = [n for n in (_target_name(t) for t in targets) if n]
        _aug_bind_names(names, rhs, env)
        return
    _apply_multi(targets, rexprs, env)


def _exec_var_spec(spec: Any, env: _Env, on_call) -> None:
    value = _field(spec, "value")
    _walk_calls(value, env, on_call)
    names = [c for c in spec.children if c.type == "identifier"]
    rexprs = _named_children(value) if value is not None else []
    if not rexprs:
        for name in names:
            env.pop(_txt(name), None)  # ``var x T`` zero value: untainted
        return
    _apply_multi(names, rexprs, env)


def _exec_if(stmt: Any, env: _Env, on_call) -> None:
    init = _field(stmt, "initializer")
    base = _copy_env(env)
    scoped = _declared_names(init) if init is not None else []
    if init is not None:
        _exec_stmt(init, base, on_call)
    _walk_calls(_field(stmt, "condition"), base, on_call)
    body_env = _copy_env(base)
    _exec_stmt(_field(stmt, "consequence"), body_env, on_call)
    else_env = _copy_env(base)
    alt = _field(stmt, "alternative")
    if alt is not None:
        _exec_stmt(alt, else_env, on_call)
    merged = _join(body_env, else_env)
    for name in scoped:
        merged.pop(name, None)  # the init var is scoped to the if
    _set_env(env, merged)


def _exec_for(stmt: Any, env: _Env, on_call) -> None:
    body = _field(stmt, "body")
    clause = None
    for child in stmt.children:
        if child.type in ("for_clause", "range_clause"):
            clause = child
            break

    if clause is None:  # ``for { ... }`` infinite loop
        for _ in range(2):
            body_env = _copy_env(env)
            _exec_stmt(body, body_env, on_call)
            _set_env(env, _join(env, body_env))
        return

    if clause.type == "for_clause":
        init = _field(clause, "initializer")
        scoped = _declared_names(init) if init is not None else []
        base = _copy_env(env)
        if init is not None:
            _exec_stmt(init, base, on_call)
        _walk_calls(_field(clause, "condition"), base, on_call)
        update = _field(clause, "update")
        for _ in range(2):
            body_env = _copy_env(base)
            _exec_stmt(body, body_env, on_call)
            if update is not None:
                _exec_stmt(update, body_env, on_call)
            base = _join(base, body_env)  # entry (0-iteration) env retained
        for name in scoped:
            base.pop(name, None)
        _set_env(env, base)
        return

    # range_clause: ``for k, v := range coll``
    right = _field(clause, "right")
    _walk_calls(right, env, on_call)
    iter_taint = _real(_taint_of_expr(right, env))
    left = _field(clause, "left")
    ltargets = _named_children(left) if left is not None else []
    is_decl = any(c.type == ":=" for c in clause.children)
    for _ in range(2):
        body_env = _copy_env(env)
        # A 2-var range taints the VALUE (index 1); the key/index stays untainted
        # (we cannot prove the collection is a map). A 1-var range binds the
        # key/index only, so it is untainted.
        if len(ltargets) >= 2:
            key_name = _target_name(ltargets[0])
            val_name = _target_name(ltargets[1])
            if key_name:
                body_env.pop(key_name, None)
            if val_name:
                if iter_taint:
                    body_env[val_name] = set(iter_taint)
                else:
                    body_env.pop(val_name, None)
        elif len(ltargets) == 1:
            key_name = _target_name(ltargets[0])
            if key_name:
                body_env.pop(key_name, None)
        _exec_stmt(body, body_env, on_call)
        _set_env(env, _join(env, body_env))
    if is_decl:
        for target in ltargets:
            name = _target_name(target)
            if name:
                env.pop(name, None)  # range vars are scoped to the loop body


def _exec_expr_switch(stmt: Any, env: _Env, on_call) -> None:
    init = _field(stmt, "initializer")
    base = _copy_env(env)
    scoped = _declared_names(init) if init is not None else []
    if init is not None:
        _exec_stmt(init, base, on_call)
    value = _field(stmt, "value")
    _walk_calls(value, base, on_call)
    case_envs: list[_Env] = []
    has_default = False
    for case in _named_children(stmt):
        if case.type == "expression_case":
            case_env = _copy_env(base)
            label = _field(case, "value")
            _walk_calls(label, case_env, on_call)
            _exec_case_body(case, case_env, on_call, skip=label)
            case_envs.append(case_env)
        elif case.type == "default_case":
            has_default = True
            case_env = _copy_env(base)
            _exec_case_body(case, case_env, on_call)
            case_envs.append(case_env)
    if not has_default:
        case_envs.append(_copy_env(base))  # the no-match path
    merged = _join(*case_envs) if case_envs else base
    for name in scoped:
        merged.pop(name, None)
    _set_env(env, merged)


def _exec_type_switch(stmt: Any, env: _Env, on_call) -> None:
    value = _field(stmt, "value")
    _walk_calls(value, env, on_call)
    val_taint = _real(_taint_of_expr(value, env))
    alias = _field(stmt, "alias")
    alias_name: str | None = None
    if alias is not None:
        ids = [c for c in alias.children if c.type == "identifier"]
        if ids:
            alias_name = _txt(ids[0])
    case_envs: list[_Env] = []
    has_default = False
    for case in _named_children(stmt):
        if case.type not in ("type_case", "default_case"):
            continue
        if case.type == "default_case":
            has_default = True
        case_env = _copy_env(env)
        if alias_name is not None:
            if val_taint:
                case_env[alias_name] = set(val_taint)  # ``x.(type)`` is transparent
            else:
                case_env.pop(alias_name, None)
        _exec_case_body(case, case_env, on_call)
        case_envs.append(case_env)
    if not has_default:
        no_match = _copy_env(env)
        if alias_name is not None:
            no_match.pop(alias_name, None)
        case_envs.append(no_match)
    merged = _join(*case_envs) if case_envs else _copy_env(env)
    if alias_name is not None:
        merged.pop(alias_name, None)  # the alias is scoped to the type switch
    _set_env(env, merged)


def _exec_select(stmt: Any, env: _Env, on_call) -> None:
    case_envs: list[_Env] = []
    has_default = False
    for case in _named_children(stmt):
        if case.type == "communication_case":
            case_env = _copy_env(env)
            comm = _field(case, "communication")
            if comm is not None and comm.type == "receive_statement":
                # A channel receive is NOT a recognised source: kill its targets.
                left = _field(comm, "left")
                for target in _named_children(left) if left is not None else []:
                    name = _target_name(target)
                    if name:
                        case_env.pop(name, None)
            _exec_case_body(case, case_env, on_call, skip=comm)
            case_envs.append(case_env)
        elif case.type == "default_case":
            has_default = True
            case_env = _copy_env(env)
            _exec_case_body(case, case_env, on_call)
            case_envs.append(case_env)
    if not has_default:
        case_envs.append(_copy_env(env))
    if case_envs:
        _set_env(env, _join(*case_envs))


def _exec_stmt(stmt: Any, env: _Env, on_call) -> None:
    """Apply one statement to ``env`` in order (see module docstring for rules)."""
    if stmt is None:
        return
    t = stmt.type

    if t in _SKIP_SUBTREES:
        return  # func literal / goroutine / deferred / channel send

    if t == "block":
        _exec_block(stmt, env, on_call)
        return

    if t == "labeled_statement":
        inner = _named_children(stmt)
        if inner:
            _exec_stmt(inner[-1], env, on_call)
        return

    if t == "short_var_declaration":
        _exec_assign(stmt, env, on_call, decl=True)
        return

    if t == "assignment_statement":
        _exec_assign(stmt, env, on_call, decl=False)
        return

    if t in ("var_declaration", "const_declaration"):
        for child in _named_children(stmt):
            if child.type in ("var_spec", "const_spec"):
                _exec_var_spec(child, env, on_call)
            elif child.type in ("var_spec_list", "const_spec_list"):
                for spec in _named_children(child):
                    if spec.type in ("var_spec", "const_spec"):
                        _exec_var_spec(spec, env, on_call)
        return

    if t == "expression_statement":
        for child in _named_children(stmt):
            _walk_calls(child, env, on_call)
        return

    if t == "if_statement":
        _exec_if(stmt, env, on_call)
        return

    if t == "for_statement":
        _exec_for(stmt, env, on_call)
        return

    if t == "expression_switch_statement":
        _exec_expr_switch(stmt, env, on_call)
        return

    if t == "type_switch_statement":
        _exec_type_switch(stmt, env, on_call)
        return

    if t == "select_statement":
        _exec_select(stmt, env, on_call)
        return

    # return / inc / dec / go-less expression / ... : fire the calls they hold.
    _walk_calls(stmt, env, on_call)


def _run_flow(fnode: Any, env: _Env, on_call) -> _Env:
    """Flow-sensitive walk of ``fnode``'s block body; mutate and return ``env``."""
    body = _field(fnode, "body")
    if body is not None and body.type == "block":
        _exec_block(body, env, on_call)
    return env


# --------------------------------------------------------------------------
# Parameters (ordered positional slots) + argument binding
# --------------------------------------------------------------------------


@dataclass
class _ParamSlot:
    names: list[str]  # the simple names this positional param binds
    bindable: bool  # False for an unnamed typed slot (never bound)


def _positional_param_slots(fnode: Any) -> tuple[list[_ParamSlot], bool]:
    """Ordered positional parameter slots and whether a variadic (``...T``) exists.

    A grouped declaration ``(a, b string)`` yields one slot PER name (two slots).
    An unnamed typed parameter ``func(int)`` is a non-bindable slot (occupies a
    position but is never bound). A variadic parameter sets the ``has_variadic``
    flag (binding is then declined). The receiver is a separate field, so a
    method's receiver is never a positional parameter.
    """
    params = _field(fnode, "parameters")
    if params is None:
        return [], False
    slots: list[_ParamSlot] = []
    has_variadic = False
    for child in _named_children(params):
        if child.type == "parameter_declaration":
            names = [c for c in child.children if c.type == "identifier"]
            if names:
                for name in names:
                    slots.append(_ParamSlot([_txt(name)], True))
            else:
                slots.append(_ParamSlot([], False))  # unnamed typed param
        elif child.type == "variadic_parameter_declaration":
            has_variadic = True
    return slots, has_variadic


def _call_args(call: Any) -> list[Any]:
    arglist = _field(call, "arguments")
    if arglist is None:
        return []
    return [c for c in arglist.children if c.is_named]


def _call_has_spread(call: Any) -> bool:
    """True for a spread call ``f(xs...)`` (a ``variadic_argument`` node)."""
    arglist = _field(call, "arguments")
    if arglist is None:
        return False
    return any(c.type == "variadic_argument" for c in arglist.children)


def _bind_call_args(call: Any, next_fnode: Any, env: _Env, seed: _Env) -> None:
    """Bind tainted arguments of ``call`` to ``next_fnode``'s parameters.

    Binding is declined for a spread argument, a variadic callee parameter, or
    more positional arguments than bindable positional parameters (conservative:
    a missed flow, never a guessed one).
    """
    if _call_has_spread(call):
        return
    args = _call_args(call)
    slots, has_variadic = _positional_param_slots(next_fnode)
    if has_variadic or len(args) > len(slots):
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


def _handler_seed(fnode: Any) -> _Env:
    """Seed request/context sources from a handler's typed parameters.

    Each parameter whose type is ``*http.Request`` / ``*gin.Context`` /
    ``echo.Context`` seeds its name(s) with the matching identity sentinel; every
    other parameter (``http.ResponseWriter``, ``error``, ...) seeds nothing.
    """
    env: _Env = {}
    params = _field(fnode, "parameters")
    if params is None:
        return env
    for child in _named_children(params):
        if child.type != "parameter_declaration":
            continue
        sentinel = _seed_sentinel_for_type(_txt(_field(child, "type")))
        if sentinel is None:
            continue
        for name in (c for c in child.children if c.type == "identifier"):
            env[_txt(name)] = {sentinel}
    return env


# --------------------------------------------------------------------------
# Parsed-file cache
# --------------------------------------------------------------------------


@dataclass
class _GoFile:
    """Everything the pass needs about one re-parsed Go source file."""

    root: Any
    defs: dict[str, Any]  # qualname -> fn/method declaration node
    local_funcs: set[str]  # non-method qualnames declared in this file
    pkg_map: dict[str, tuple[str, str]]  # import name -> (dep_id, import_path)
    stdlib: set[str]  # stdlib import paths
    local_pkg_map: dict[str, dict[str, Any]]  # import name -> local package info
    pkg_funcs: dict[str, str]  # bare same-package name -> fn_id (own directory)
    relpath: str
    analyzer: GoAnalyzer


class _FileCache:
    """Re-scans the repo once (for the dep graph + cross-package index), then
    lazily re-parses and caches the Go files the pass touches.

    The analyzer's import resolution needs the manifest's ``dep:Go:*`` nodes, the
    single-module path and the per-package export index. Neither is handed to the
    adapter by the core, so the cache rebuilds them exactly as
    :func:`scanner.scan.scan_repo` does (walk -> dependencies -> repo index). The
    rebuilt graph is a throwaway used only to answer "does this package exist".
    """

    def __init__(self, repo_root: str) -> None:
        self._analyzer = GoAnalyzer()
        self._cache: dict[str, _GoFile | None] = {}
        self._graph, self._repo_index, self._source_cache = _scan_support(repo_root)
        self._dep_index = self._analyzer._go_dep_index(self._graph)
        self._go_module = self._repo_index.get("go_module")
        self._go_packages = self._repo_index.get("go_packages", {})
        # dir relpath -> {bare name: fn_id} for same-package cross-file resolution.
        self._go_package_funcs = self._repo_index.get("go_package_funcs", {})

    def get(self, relpath: str) -> _GoFile | None:
        if relpath in self._cache:
            return self._cache[relpath]
        parsed = self._parse(relpath)
        self._cache[relpath] = parsed
        return parsed

    def _parse(self, relpath: str) -> _GoFile | None:
        source = self._source_cache.get(relpath)
        if source is None:
            return None
        try:
            root = get_parser("go").parse(source.encode("utf-8")).root_node
        except Exception:  # pragma: no cover - parser never raises on bytes
            return None
        try:
            functions = self._analyzer._collect_functions(root)
            pkg_map, stdlib, local_pkg_map, _unresolved = self._analyzer._process_imports(
                root,
                f"mod:{relpath}",
                self._dep_index,
                self._graph,
                self._go_module,
                self._go_packages,
            )
        except Exception:  # pathological source: not analysable -> not_proven
            return None
        defs = {qual: node for qual, node, _is_method, _ptr in functions}
        local_funcs = {
            qual for qual, _n, is_method, _p in functions if not is_method
        }
        return _GoFile(
            root=root,
            defs=defs,
            local_funcs=local_funcs,
            pkg_map=pkg_map,
            stdlib=stdlib,
            local_pkg_map=local_pkg_map,
            pkg_funcs=self._go_package_funcs.get(os.path.dirname(relpath), {}),
            relpath=relpath,
            analyzer=self._analyzer,
        )


# --------------------------------------------------------------------------
# Call resolution (delegated to the real analyzer)
# --------------------------------------------------------------------------


def _resolve(file_info: _GoFile, call: Any, bound: set[str]) -> tuple[str, ...]:
    """Resolve a call via the real analyzer (bound names computed per function)."""
    return file_info.analyzer._resolve_call(
        call,
        file_info.pkg_map,
        file_info.stdlib,
        bound,
        file_info.local_funcs,
        file_info.relpath,
        file_info.local_pkg_map,
        file_info.pkg_funcs,
    )


# --------------------------------------------------------------------------
# FnInfo + the adapter
# --------------------------------------------------------------------------


@dataclass
class _FnInfo:
    """Opaque per-function info handed back to the driver (see the Protocol)."""

    file: _GoFile
    node: Any
    qual: str
    relpath: str
    fn_id: str


class GoTaintAdapter:
    """:class:`scanner.taint.core.TaintAdapter` for Go source.

    ``cache`` is a :class:`_FileCache`; ``*_info`` objects are :class:`_FnInfo`.
    """

    def language_matches(self, relpath: str) -> bool:
        return relpath.endswith(".go")

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
        node = parsed.defs.get(qual)
        if node is None:
            return None
        return _FnInfo(
            file=parsed, node=node, qual=qual, relpath=relpath, fn_id=fn_id
        )

    def handler_seed(self, fn_info: _FnInfo) -> _Env:
        return _handler_seed(fn_info.node)

    def bind_into_next(
        self, caller_info: _FnInfo, env: _Env, next_info: _FnInfo
    ) -> _Env:
        seed: _Env = {}
        bound = caller_info.file.analyzer._bound_names(caller_info.node)

        def on_call(call: Any, call_env: _Env) -> None:
            result = _resolve(caller_info.file, call, bound)
            if len(result) >= 2 and result[0] == "fn" and result[1] == next_info.fn_id:
                _bind_call_args(call, next_info.node, call_env, seed)

        _run_flow(caller_info.node, env, on_call)
        return seed

    def detect_sink(
        self, sink_info: _FnInfo, env: _Env, dep_symbols: set[str], dep_id: str
    ) -> tuple[str, str] | None:
        found: list[tuple[str, str]] = []
        bound = sink_info.file.analyzer._bound_names(sink_info.node)

        def on_call(call: Any, call_env: _Env) -> None:
            if found:
                return
            result = _resolve(sink_info.file, call, bound)
            # Gate: a ``("dep", id, symbol)`` sink whose id is THIS dependency and
            # whose symbol is one of the advisory's. Requiring ``result[1] ==
            # dep_id`` (defense-in-depth) stops a symbol match attributing to a
            # different dep that happens to share the symbol name.
            if (
                len(result) < 3
                or result[0] != "dep"
                or result[1] != dep_id
                or result[2] not in dep_symbols
            ):
                return
            for arg in _call_args(call):
                if arg.type == "variadic_argument":
                    continue
                taint = _real(_taint_of_expr(arg, call_env))
                if taint:
                    found.append((result[2], sorted(taint)[0]))
                    return

        _run_flow(sink_info.node, env, on_call)
        return found[0] if found else None
