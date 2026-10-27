"""Python adapter for the taint pass (layer 1).

This is the FIRST (and, today, only) language adapter behind the grammar-free
core in :mod:`scanner.taint.core`. It answers the core's questions for Python
source: parsing, ``request``-object source recognition, flow-sensitive
intra-procedural propagation, argument->parameter binding, call-site resolution,
and dependency-symbol sink matching. All ``ast`` handling lives here; the core
knows nothing about it.

It re-parses the Python source of the functions ON a proven reachability path
(``entrypoint -> handler -> ... -> dependency``) and checks whether a *source*
(an attacker-controlled read at the handler) propagates -- through
taint-preserving operations and proven argument/parameter bindings -- all the way
into the *sink* (the call into the dependency).

THE CARDINAL RULE (see :mod:`scanner.taint.core`)
-------------------------------------------------
Never assert a claim unless fully proven. A MISSED taint flow is acceptable; a
FALSE "tainted" claim is a CRITICAL failure. The default verdict is
``not_proven``.

Deliberate conservative limitations (documented, not bugs)
----------------------------------------------------------
* Only Python source/sink recognition is implemented.
* Return values of arbitrary function calls are NEVER treated as tainted. A flow
  that launders attacker data through an unmodelled helper's return value is
  therefore MISSED (sound: a missed flow, never a false one).
* Argument->parameter binding is declined for ``*args``/``**kwargs`` and for a
  call that passes more positional arguments than the callee has named
  positional parameters.
* Taint is tracked for simple names only. Writing a tainted value into a
  subscript/attribute target (``obj.x = tainted``) does not taint ``obj`` (a
  missed flow).
* Propagation is flow-sensitive with a proper MAY-dataflow JOIN at every
  control-flow merge. An ordered walk maintains the current tainted name-set:
  on straight-line code a reassignment to a non-tainted value KILLS the name
  (last-write-wins). At a merge (``if``/``else``, ``match``, a loop back-edge,
  ``try``) a name survives iff it survives on ANY incoming path, with its
  provenance the union over those paths -- so a kill on one path alone cannot
  refute taint, but a kill on EVERY path does (an ``if``/``else`` that overwrites
  a name to a constant on both arms kills it). ``with``/``async with`` bodies
  always execute and are treated as straight-line (kills apply). Loop bodies
  (``for``/``while``/``async for``) run 0+ times: the entry env is the
  0-iteration path (so a loop-body kill never removes taint) and a two-pass
  fixpoint approximates taint that grows across iterations. ``tainted`` is the
  existential claim "some execution reaches the sink tainted". The sink check
  and the argument->parameter bind both read the taint state AT the call's
  position (branch bodies run on COPIES, so a call inside a branch sees that
  branch's local env, and a call after the branch sees the joined env). A name
  that is ONLY ever a constant (even if named like a source, e.g. ``data``) is
  NOT tainted.
* A guaranteed-infinite loop whose body UNCONDITIONALLY kills a name is a rare,
  accepted over-approximation: the two-pass loop model always retains the
  0-iteration (entry) env, so such a name stays tainted even though no real
  execution exits with it. This keeps taint (never drops a real flow) and is
  sound in the ``tainted``-is-existential direction.
* Argument->parameter binding only fires from a call that PROVABLY resolves to
  the specific on-path callee (a module-level function reached by an import of
  its module or a same-module sibling call, or a method reached through ``self``
  in the same class or a proven instance of that class). A same-named call that
  cannot be positively resolved to the callee is NOT bound (a missed flow).
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Any

from ..analyzers.python_analyzer import (
    PythonAnalyzer,
    _collect,
    _collect_classes,
    module_path_for,
)
from .core import (
    _Env,
    _aug_bind_names,
    _assign_or_kill_names,
    _bind_names,
    _copy_env,
    _join,
    _set_env,
    _split_fn_id,
)

# The Flask/Django ``request`` object attributes that carry attacker-controlled
# data. ``requests`` (the HTTP client) is deliberately excluded: it is matched
# by resolved dependency symbols, never by this name.
_REQUEST_SOURCE_ATTRS: frozenset[str] = frozenset(
    {"args", "form", "values", "json", "data", "files", "headers", "cookies"}
)

# ``request`` method-call sources (``request.get_json(...)`` / ``get_data(...)``).
_REQUEST_SOURCE_METHODS: frozenset[str] = frozenset({"get_json", "get_data"})

# The one name that denotes the Flask/Django request object (and, by convention,
# the FastAPI ``Request`` parameter -- see ``_handler_param_sources``).
_REQUEST_NAME: str = "request"


# --------------------------------------------------------------------------
# Parsed-file cache
# --------------------------------------------------------------------------


@dataclass
class _ParsedFile:
    """Everything the pass needs about one re-parsed Python source file."""

    defs: dict[str, ast.AST]  # qualname -> def node
    method_meta: dict[str, tuple[str, str | None]]  # qual -> (class_qual, self)
    import_aliases: dict[str, str]  # bound name -> dotted import base


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map each imported bound name to its absolute dotted base.

    Built the same way the analyzer resolves imports, but kept deliberately
    simple because it is only ever used to RECONSTRUCT a call's dotted name and
    match it against an already-proven dependency symbol -- it can recover a
    sink match, never fabricate one. Relative imports are skipped.

    * ``import a.b.c``        -> ``a`` : ``a``
    * ``import a.b.c as x``   -> ``x`` : ``a.b.c``
    * ``import yaml as y``    -> ``y`` : ``yaml``
    * ``from m import f``     -> ``f`` : ``m.f``
    * ``from m import f as g``-> ``g`` : ``m.f``
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or (node.level or 0) > 0:
                continue
            for alias in node.names:
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


class _FileCache:
    """Lazily re-parses and caches the Python files the pass touches."""

    def __init__(self, repo_root: str) -> None:
        self._root = repo_root
        self._cache: dict[str, _ParsedFile | None] = {}

    def get(self, relpath: str) -> _ParsedFile | None:
        if relpath in self._cache:
            return self._cache[relpath]
        parsed = self._parse(relpath)
        self._cache[relpath] = parsed
        return parsed

    def _parse(self, relpath: str) -> _ParsedFile | None:
        abspath = os.path.join(self._root, relpath)
        try:
            with open(abspath, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError:
            return None
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return None
        functions, _ = _collect(tree)
        _, method_meta = _collect_classes(tree)
        return _ParsedFile(
            defs={qual: node for qual, node in functions},
            method_meta=method_meta,
            import_aliases=_import_aliases(tree),
        )


# --------------------------------------------------------------------------
# Source recognition
# --------------------------------------------------------------------------


def _is_request_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == _REQUEST_NAME


def _attr_source(node: ast.Attribute) -> str | None:
    """``request.<attr>`` attribute source -> its descriptor, else ``None``."""
    # Walk down to the root of the attribute chain.
    cur: ast.AST = node
    attrs: list[str] = []
    while isinstance(cur, ast.Attribute):
        attrs.append(cur.attr)
        cur = cur.value
    attrs.reverse()
    if _is_request_name(cur) and attrs and attrs[0] in _REQUEST_SOURCE_ATTRS:
        return f"{_REQUEST_NAME}.{attrs[0]}"
    return None


def _source_of(node: ast.AST) -> str | None:
    """Return a source descriptor if ``node`` reads attacker data, else ``None``.

    Recognises ONLY reads from the Flask/Django ``request`` object:

    * attribute access: ``request.args`` / ``.form`` / ``.values`` / ``.json`` /
      ``.data`` / ``.files`` / ``.headers`` / ``.cookies``;
    * method calls: ``request.get_json(...)`` / ``request.get_data(...)``;
    * a getter called on any of the attribute sources above
      (``request.args.get(...)``, ``request.form.getlist(...)``, ...).

    It never matches the ``requests`` HTTP-client library.
    """
    if isinstance(node, ast.Attribute):
        return _attr_source(node)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _REQUEST_SOURCE_METHODS and _is_request_name(func.value):
                return f"{_REQUEST_NAME}.{func.attr}"
            # A getter on a request source attribute, e.g. ``request.args.get``.
            inner = _source_of(func.value)
            if inner is not None:
                return inner
    return None


# --------------------------------------------------------------------------
# Intra-procedural propagation (flow-sensitive straight-line, union-on-branch)
# --------------------------------------------------------------------------


def _taint_of_expr(node: ast.AST | None, env: _Env) -> set[str]:
    """Provenance set of ``node`` under ``env``, via taint-preserving ops only.

    Returns the union of source descriptors that flow to the value of ``node``.
    An empty set means "not proven tainted". Only the operations explicitly
    enumerated below preserve taint; every other construct -- crucially, an
    arbitrary function-call return value -- yields the empty set.
    """
    if node is None:
        return set()

    # Leaf: a source read.
    src = _source_of(node)
    if src is not None:
        return {src}

    if isinstance(node, ast.Name):
        return set(env.get(node.id, set()))

    if isinstance(node, ast.Constant):
        return set()

    # Attribute access on a tainted value: ``x.attr`` (x tainted -> tainted).
    if isinstance(node, ast.Attribute):
        return _taint_of_expr(node.value, env)

    # Subscript: ``x[...]`` (x tainted -> tainted).
    if isinstance(node, ast.Subscript):
        return _taint_of_expr(node.value, env)

    if isinstance(node, ast.Starred):
        return _taint_of_expr(node.value, env)

    # String concat / `%` / arithmetic: taint of either operand.
    if isinstance(node, ast.BinOp):
        return _taint_of_expr(node.left, env) | _taint_of_expr(node.right, env)

    if isinstance(node, ast.BoolOp):
        out: set[str] = set()
        for value in node.values:
            out |= _taint_of_expr(value, env)
        return out

    # ``a if cond else b``: either branch may supply the value.
    if isinstance(node, ast.IfExp):
        return _taint_of_expr(node.body, env) | _taint_of_expr(node.orelse, env)

    # f-string.
    if isinstance(node, ast.JoinedStr):
        out = set()
        for value in node.values:
            out |= _taint_of_expr(value, env)
        return out
    if isinstance(node, ast.FormattedValue):
        return _taint_of_expr(node.value, env)

    # Container literals holding a tainted element.
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out = set()
        for elt in node.elts:
            out |= _taint_of_expr(elt, env)
        return out
    if isinstance(node, ast.Dict):
        out = set()
        for key in node.keys:
            out |= _taint_of_expr(key, env)
        for value in node.values:
            out |= _taint_of_expr(value, env)
        return out

    # Comprehensions: bind the comprehension targets from their (tainted)
    # iterables in a local env, then evaluate the element expression.
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        local = _comprehension_env(node.generators, env)
        return _taint_of_expr(node.elt, local)
    if isinstance(node, ast.DictComp):
        local = _comprehension_env(node.generators, env)
        return _taint_of_expr(node.key, local) | _taint_of_expr(node.value, local)

    # Walrus: its value is the expression's value (the binding itself is handled
    # by the statement pass).
    if isinstance(node, ast.NamedExpr):
        return _taint_of_expr(node.value, env)

    # ``"...".format(tainted)`` / ``tainted.format(...)`` -- taint-preserving.
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            out = _taint_of_expr(func.value, env)
            for arg in node.args:
                out |= _taint_of_expr(arg, env)
            for kw in node.keywords:
                out |= _taint_of_expr(kw.value, env)
            return out
        # Every other call: the return value is NOT proven tainted.
        return set()

    return set()


def _comprehension_env(generators: list[ast.comprehension], env: _Env) -> _Env:
    """Env extended with comprehension targets tainted from tainted iterables."""
    local: _Env = dict(env)
    for gen in generators:
        iter_taint = _taint_of_expr(gen.iter, local)
        if iter_taint:
            _bind_target(gen.target, iter_taint, local)
    return local


# --------------------------------------------------------------------------
# Target binding: walk a Python assignment target into simple names, then apply
# the grammar-free name-level env algebra from the core.
# --------------------------------------------------------------------------


def _flatten_target(target: ast.AST) -> list[str]:
    """Simple names bound by ``target`` (over-approximating tuple/list unpack).

    A bare ``Name`` yields itself. A tuple/list target yields every simple name
    it contains -- a SOUND over-approximation, since unpacking a tainted RHS
    could route the tainted element to any of them. A ``Starred`` recurses into
    its value. Subscript/attribute targets bind no simple name (a missed flow --
    never a false one) and so yield nothing; this is also what keeps an
    ``obj.x = const`` from killing a same-named plain variable.
    """
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(_flatten_target(elt))
        return out
    if isinstance(target, ast.Starred):
        return _flatten_target(target.value)
    return []


def _bind_target(target: ast.AST, taint: set[str], env: _Env) -> None:
    """Mark the name(s) bound by ``target`` tainted with ``taint`` (union, add-only)."""
    _bind_names(_flatten_target(target), taint, env)


def _assign_or_kill(target: ast.AST, taint: set[str], env: _Env) -> None:
    """Last-write-wins bind of ``target``: set it tainted, or KILL it if not."""
    _assign_or_kill_names(_flatten_target(target), taint, env)


def _aug_bind(target: ast.AST, rhs_taint: set[str], env: _Env) -> None:
    """``x += y``: x becomes/stays tainted if x-was-tainted OR y-tainted; never kills."""
    _aug_bind_names(_flatten_target(target), rhs_taint, env)


def _eval_expr(node: ast.AST | None, env: _Env, on_call) -> None:
    """Fire ``on_call`` for every call in ``node`` and apply walrus bindings.

    Used for the straight-line expressions of a statement (an assignment's RHS, a
    branch condition/iterable, a bare expression, a ``return``/``raise`` value,
    ...). ``on_call(call, env)`` sees the taint state at the call's position. A
    walrus (``x := v``) binds its target with last-write-wins semantics against
    the current ``env`` (so a straight-line ``x := const`` kills ``x``).
    """
    if node is None:
        return
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            on_call(child, env)
        elif isinstance(child, ast.NamedExpr):
            _assign_or_kill(child.target, _taint_of_expr(child.value, env), env)


_TRY_TYPES: tuple[type, ...] = (
    (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
)


def _is_catch_all_case(case) -> bool:
    """True for an unguarded ``case _:`` / bare ``case name:`` (matches anything).

    A guarded case can always fail its guard, so it is never catch-all. Only an
    unconditional capture/wildcard (``MatchAs`` with no sub-pattern) is treated
    as exhaustive; anything we fail to recognise leaves the no-match path in the
    join, which keeps taint (sound in the ``tainted``-is-existential direction).
    """
    if case.guard is not None:
        return False
    pattern = case.pattern
    return isinstance(pattern, ast.MatchAs) and pattern.pattern is None


def _exec_suite(stmts: list[ast.AST], env: _Env, on_call) -> None:
    for stmt in stmts:
        _exec_stmt(stmt, env, on_call)


def _apply_optional_branch(body: list[ast.AST], env: _Env, on_call) -> None:
    """Join a branch that MAY or may not execute back into ``env``.

    The body runs on a COPY of ``env``; the result is JOINed with the entry
    ``env`` (the path that skips the branch). Taint killed only inside the body
    therefore survives via the skip path, while taint the body ADDS is kept.
    Used for an ``if`` with no ``else`` and for loop/``try`` ``else`` clauses.
    """
    if not body:
        return
    branch_env = _copy_env(env)
    _exec_suite(body, branch_env, on_call)
    _set_env(env, _join(env, branch_env))


def _apply_loop_body(
    body: list[ast.AST],
    env: _Env,
    on_call,
    target: ast.AST | None = None,
    iter_taint: set[str] | None = None,
) -> None:
    """Join a loop body (runs 0+ times) into ``env`` with a 2-pass fixpoint.

    The entry ``env`` is the 0-iteration path and is retained in every join, so
    a kill INSIDE the body never removes a name from the enclosing env. Two
    passes approximate a fixpoint for taint that grows across iterations (enough
    for these finite source sets). A ``for`` target is (re)bound at the top of
    each pass -- tainted iff the iterable is, KILLED otherwise -- so an attacker
    name shadowed by a non-tainted loop target is not seen tainted in the body.
    """
    if not body and target is None:
        return
    for _ in range(2):
        body_env = _copy_env(env)
        if target is not None:
            _assign_or_kill(target, iter_taint or set(), body_env)
        _exec_suite(body, body_env, on_call)
        _set_env(env, _join(env, body_env))


def _exec_stmt(stmt: ast.AST, env: _Env, on_call) -> None:
    """Apply one statement to ``env`` in order (see module docstring for rules)."""
    # Nested scopes bind their own names; never descend (a name bound there is
    # not this function's name).
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return

    if isinstance(stmt, ast.Assign):
        _eval_expr(stmt.value, env, on_call)
        taint = _taint_of_expr(stmt.value, env)
        for target in stmt.targets:
            _assign_or_kill(target, taint, env)
        return
    if isinstance(stmt, ast.AnnAssign):
        if stmt.value is not None:
            _eval_expr(stmt.value, env, on_call)
            _assign_or_kill(stmt.target, _taint_of_expr(stmt.value, env), env)
        return
    if isinstance(stmt, ast.AugAssign):
        _eval_expr(stmt.value, env, on_call)
        _aug_bind(stmt.target, _taint_of_expr(stmt.value, env), env)
        return

    if isinstance(stmt, ast.If):
        _eval_expr(stmt.test, env, on_call)  # condition is straight-line
        # Both arms run on COPIES of the entry env, then JOIN. An implicit empty
        # ``else`` is the entry env unchanged (a copy), so a name killed on both
        # arms dies while a name killed on only one survives via the other.
        body_env = _copy_env(env)
        _exec_suite(stmt.body, body_env, on_call)
        else_env = _copy_env(env)
        if stmt.orelse:
            _exec_suite(stmt.orelse, else_env, on_call)
        _set_env(env, _join(body_env, else_env))
        return
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        _eval_expr(stmt.iter, env, on_call)
        iter_taint = _taint_of_expr(stmt.iter, env)
        _apply_loop_body(stmt.body, env, on_call, stmt.target, iter_taint)
        _apply_optional_branch(stmt.orelse, env, on_call)
        return
    if isinstance(stmt, ast.While):
        _eval_expr(stmt.test, env, on_call)
        _apply_loop_body(stmt.body, env, on_call)
        _apply_optional_branch(stmt.orelse, env, on_call)
        return
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        # The body ALWAYS executes -> straight-line in the current env (kills
        # apply). Bind each ``as`` target before the body.
        for item in stmt.items:
            _eval_expr(item.context_expr, env, on_call)
        for item in stmt.items:
            if item.optional_vars is not None:
                _assign_or_kill(
                    item.optional_vars,
                    _taint_of_expr(item.context_expr, env),
                    env,
                )
        _exec_suite(stmt.body, env, on_call)
        return
    if isinstance(stmt, _TRY_TYPES):
        # Conservative may-JOIN over the possible exit states: the body ran
        # (fully or partially), any handler caught, or (if present) the ``else``
        # ran after the body succeeded. ``finally`` always runs -> straight-line
        # on the joined env. Residual: a partially-executed body that raised is
        # approximated by its full straight-line effect (kept simple).
        try_env = _copy_env(env)
        _exec_suite(stmt.body, try_env, on_call)
        exit_envs: list[_Env] = [try_env]
        for handler in stmt.handlers:
            if handler.type is not None:
                _eval_expr(handler.type, env, on_call)
            handler_env = _copy_env(env)
            _exec_suite(handler.body, handler_env, on_call)
            exit_envs.append(handler_env)
        if stmt.orelse:
            orelse_env = _copy_env(try_env)
            _exec_suite(stmt.orelse, orelse_env, on_call)
            exit_envs.append(orelse_env)
        _set_env(env, _join(*exit_envs))
        _exec_suite(stmt.finalbody, env, on_call)
        return
    if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
        _eval_expr(stmt.subject, env, on_call)  # subject is straight-line
        case_envs: list[_Env] = []
        has_catch_all = False
        for case in stmt.cases:
            case_env = _copy_env(env)
            if case.guard is not None:
                _eval_expr(case.guard, case_env, on_call)
            _exec_suite(case.body, case_env, on_call)
            case_envs.append(case_env)
            if _is_catch_all_case(case):
                has_catch_all = True
        if not has_catch_all:
            # No wildcard/catch-all case: the no-match fall-through path (entry
            # env unchanged) is also a possible exit.
            case_envs.append(_copy_env(env))
        if case_envs:
            _set_env(env, _join(*case_envs))
        return

    # Any other simple statement (Expr, Return, Raise, Assert, Delete, ...):
    # fire calls / apply walruses in whatever expressions it contains.
    _eval_expr(stmt, env, on_call)


def _run_flow(fnode: ast.AST, env: _Env, on_call) -> _Env:
    """Flow-sensitive walk of ``fnode``; mutate and return the final ``env``.

    ``env`` is the seed (bound parameters + request sources are picked up where
    they are read). ``on_call(call, env)`` fires for every call in source order
    with the taint state AT that call.
    """
    _exec_suite(getattr(fnode, "body", []), env, on_call)
    return env


def _propagate(fnode: ast.AST, env: _Env) -> _Env:
    """Flow-sensitive propagation over ``fnode``, returning the final env.

    Convenience wrapper (no call callback) used by the unit tests; the per-path
    analysis uses :func:`_run_flow` with a callback so it can read the taint
    state at the exact position of a bind/sink call.
    """
    return _run_flow(fnode, env, lambda _call, _env: None)


# --------------------------------------------------------------------------
# Parameter ordering / argument binding
# --------------------------------------------------------------------------


def _positional_params(fnode: ast.AST) -> list[str]:
    """Ordered positional parameter names (posonly + normal), no ``self`` skip."""
    args = getattr(fnode, "args", None)
    if not isinstance(args, ast.arguments):
        return []
    return [a.arg for a in list(args.posonlyargs) + list(args.args)]


def _all_param_names(fnode: ast.AST) -> set[str]:
    args = getattr(fnode, "args", None)
    if not isinstance(args, ast.arguments):
        return set()
    return PythonAnalyzer._arg_names(args)


def _call_has_star(call: ast.Call) -> bool:
    """True if the call uses ``*args`` or ``**kwargs`` (binding is declined)."""
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return True
    return any(kw.arg is None for kw in call.keywords)


def _call_resolves_to(
    call: ast.Call,
    caller_relpath: str,
    caller_qual: str,
    caller_parsed: _ParsedFile,
    caller_node: ast.AST,
    next_relpath: str,
    next_qual: str,
    next_is_method: bool,
) -> bool:
    """Decide, conservatively, whether ``call`` provably targets the on-path callee.

    The on-path callee is ``next_node`` (``fn:<next_relpath>:<next_qual>``), which
    the reachability engine already proved is reached from ``caller_node``. This
    re-establishes WHICH concrete call site hits it, so taint from an unrelated
    same-named call cannot leak into the callee's parameters. Ambiguous ⇒ False
    (a missed flow is acceptable; a false bind is not).

    Module-level callee (``next_qual`` a bare function name):
      * bare ``name(...)`` -- only when ``name`` is imported into the caller's
        file from the callee's module (``from <mod> import name``) or the caller
        is in that same module, and ``name`` is not locally rebound;
      * ``<alias>.name(...)`` -- only when ``<alias>`` resolves, via the caller
        file's import map, to the callee's module.
      Never ``self.name(...)`` / ``obj.name(...)`` for a module-level callee.

    Method callee (``next_qual`` == ``Class.method``):
      * ``self.method(...)`` -- only when the caller is itself a method of the
        same ``Class`` in the same file and ``self`` is its first parameter;
      * ``<var>.method(...)`` -- only when ``<var>`` is a proven instance of that
        ``Class`` in the caller (same file). Unknown receiver class ⇒ False.
      Never a bare ``method(...)`` or ``mod.method(...)`` for a method callee.
    """
    func = call.func
    callee_name = next_qual.rsplit(".", 1)[-1]

    if next_is_method:
        callee_class = next_qual.rsplit(".", 1)[0] if "." in next_qual else ""
        if not (isinstance(func, ast.Attribute) and func.attr == callee_name):
            return False
        recv = func.value
        if not isinstance(recv, ast.Name):
            return False  # multi-hop / construct-and-call receivers not modelled
        # ``self.method(...)`` within the same class, same file.
        meta = caller_parsed.method_meta.get(caller_qual)
        if meta is not None:
            caller_class, self_param = meta
            if (
                self_param is not None
                and recv.id == self_param
                and caller_relpath == next_relpath
                and caller_class == callee_class
            ):
                return True
        # ``<var>.method(...)`` where ``<var>`` is a proven instance of the class.
        if caller_relpath == next_relpath:
            instances = PythonAnalyzer._collect_instances(caller_node)
            if instances.get(recv.id) == callee_class:
                return True
        return False

    # Module-level function callee.
    callee_module = module_path_for(next_relpath)
    caller_module = module_path_for(caller_relpath)

    if isinstance(func, ast.Name):
        if func.id != callee_name:
            return False
        bound, _ = PythonAnalyzer._function_scope(caller_node)
        if func.id in bound:
            return False  # locally rebound: not the module function
        base = caller_parsed.import_aliases.get(func.id)
        if base is not None:
            return base == f"{callee_module}.{callee_name}"
        # Not imported: a bare sibling call resolves only within the same module.
        return caller_module == callee_module

    if isinstance(func, ast.Attribute):
        if func.attr != callee_name:
            return False
        recv = func.value
        if not isinstance(recv, ast.Name):
            return False
        base = caller_parsed.import_aliases.get(recv.id)
        return base is not None and base == callee_module

    return False


def _bind_call_args(
    call: ast.Call,
    next_fnode: ast.AST,
    is_method: bool,
    env: _Env,
    seed: _Env,
) -> None:
    """Bind tainted arguments of ``call`` to the next function's parameters.

    ``env`` is the (fully propagated) taint environment of the CALLING function.
    ``seed`` is the environment being built for the callee and is updated in
    place. Binding is declined entirely for ``*args``/``**kwargs`` calls and for
    a call passing more positional arguments than there are named positional
    parameters (conservative: a missed flow, never a guessed one).
    """
    if _call_has_star(call):
        return
    positional = _positional_params(next_fnode)
    # A method called as ``obj.m(...)`` / ``self.m(...)`` does not receive the
    # ``self``/``cls`` parameter as a positional argument.
    bindable = positional[1:] if (is_method and positional) else positional
    valid_names = _all_param_names(next_fnode)

    if len(call.args) > len(bindable):
        # More positional arguments than named positional params -- do not guess.
        return
    for index, arg in enumerate(call.args):
        taint = _taint_of_expr(arg, env)
        if taint:
            seed.setdefault(bindable[index], set()).update(taint)
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in valid_names:
            continue
        taint = _taint_of_expr(kw.value, env)
        if taint:
            seed.setdefault(kw.arg, set()).update(taint)


# --------------------------------------------------------------------------
# Sink matching
# --------------------------------------------------------------------------


def _reconstruct_dotted(
    func: ast.AST, bound: set[str], local_aliases: dict[str, str], imports: dict[str, str]
) -> str | None:
    """Reconstruct a call target's absolute dotted name, respecting shadowing.

    Returns e.g. ``yaml.load`` for ``y.load`` under ``import yaml as y``. A root
    name that is locally bound (a parameter or assignment target) is honoured
    only through a one-hop local alias to an unshadowed import -- exactly the
    analyzer's shadowing discipline -- so a call on a shadowing parameter never
    reconstructs to the package symbol. Returns ``None`` when the root is not an
    import (and so cannot be a dependency sink here).
    """
    if isinstance(func, ast.Name):
        root, attrs = func.id, []
    elif isinstance(func, ast.Attribute):
        attrs = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            attrs.append(cur.attr)
            cur = cur.value
        attrs.reverse()
        if not isinstance(cur, ast.Name):
            return None
        root = cur.id
    else:
        return None

    if root in bound:
        rhs = local_aliases.get(root)
        if rhs is None or rhs in bound:
            return None
        root = rhs
    base = imports.get(root)
    if base is None:
        return None
    return base + ("." + ".".join(attrs) if attrs else "")


def _detect_sink(
    fnode: ast.AST,
    seed_env: _Env,
    parsed: _ParsedFile,
    dep_symbols: set[str],
) -> tuple[str, str] | None:
    """Prove a sink flow: a tainted argument into a dependency symbol.

    Runs the flow-sensitive walk over ``fnode`` starting from ``seed_env`` and
    checks each call, AT ITS POSITION, for a reconstructed dotted name in
    ``dep_symbols`` receiving a tainted positional/keyword argument. Returns the
    first ``(sink_symbol, source_descriptor)`` found, else ``None``.
    """
    bound, local_aliases = PythonAnalyzer._function_scope(fnode)
    found: list[tuple[str, str]] = []

    def on_call(call: ast.Call, env: _Env) -> None:
        if found:
            return
        dotted = _reconstruct_dotted(
            call.func, bound, local_aliases, parsed.import_aliases
        )
        if dotted is None or dotted not in dep_symbols:
            return
        for arg in call.args:
            taint = _taint_of_expr(arg, env)
            if taint:
                found.append((dotted, sorted(taint)[0]))
                return
        for kw in call.keywords:
            taint = _taint_of_expr(kw.value, env)
            if taint:
                found.append((dotted, sorted(taint)[0]))
                return

    _run_flow(fnode, seed_env, on_call)
    return found[0] if found else None


# --------------------------------------------------------------------------
# Per-path analysis helpers
# --------------------------------------------------------------------------


def _handler_param_sources(fnode: ast.AST, env: _Env) -> None:
    """Seed a web route handler's own parameters as sources.

    Flask converter parameters and FastAPI path/query/body parameters are all
    attacker-controlled. ``self``/``cls`` are never sources. Only called for the
    handler (the first function on a proven route path), so a parameter is only
    treated as a source when the function really is a web route handler.
    """
    for name in _positional_params(fnode):
        if name in ("self", "cls"):
            continue
        env.setdefault(name, set()).add(f"param:{name}")
    args = getattr(fnode, "args", None)
    if isinstance(args, ast.arguments):
        for arg in args.kwonlyargs:
            if arg.arg not in ("self", "cls"):
                env.setdefault(arg.arg, set()).add(f"param:{arg.arg}")


def _fn_node_on_path(
    cache: _FileCache, fn_id: str
) -> tuple[_ParsedFile, ast.AST, str, str] | None:
    """Resolve a path node id to ``(parsed_file, def_node, qualname, relpath)``."""
    split = _split_fn_id(fn_id)
    if split is None:
        return None
    relpath, qual = split
    parsed = cache.get(relpath)
    if parsed is None:
        return None
    fnode = parsed.defs.get(qual)
    if fnode is None:
        return None
    return parsed, fnode, qual, relpath


def _bind_into_next(
    caller_info: tuple[_ParsedFile, ast.AST, str, str],
    env: _Env,
    next_info: tuple[_ParsedFile, ast.AST, str, str],
) -> _Env:
    """Walk the caller flow-sensitively; bind taint into the next function.

    Returns the seed environment (bound parameters) for the next function. Taint
    is bound ONLY from call sites that :func:`_call_resolves_to` proves target
    the next function, using the taint state at each such call's position.
    """
    caller_parsed, caller_node, caller_qual, caller_relpath = caller_info
    next_parsed, next_node, next_qual, next_relpath = next_info
    next_is_method = next_qual in next_parsed.method_meta
    seed: _Env = {}

    def on_call(call: ast.Call, call_env: _Env) -> None:
        if _call_resolves_to(
            call,
            caller_relpath,
            caller_qual,
            caller_parsed,
            caller_node,
            next_relpath,
            next_qual,
            next_is_method,
        ):
            _bind_call_args(call, next_node, next_is_method, call_env, seed)

    _run_flow(caller_node, env, on_call)
    return seed


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------


class PythonTaintAdapter:
    """:class:`scanner.taint.core.TaintAdapter` implementation for Python source.

    ``cache`` is a :class:`_FileCache`; ``*_info`` objects are the
    ``(parsed_file, def_node, qualname, relpath)`` tuples returned by
    :func:`_fn_node_on_path`.
    """

    def language_matches(self, relpath: str) -> bool:
        return relpath.endswith(".py")

    def make_cache(self, repo_root: str) -> _FileCache:
        return _FileCache(repo_root)

    def resolve_function(self, cache: _FileCache, fn_id: str) -> Any | None:
        return _fn_node_on_path(cache, fn_id)

    def handler_seed(self, fn_info: Any) -> _Env:
        _parsed, fnode, _qual, _relpath = fn_info
        env: _Env = {}
        _handler_param_sources(fnode, env)
        return env

    def bind_into_next(self, caller_info: Any, env: _Env, next_info: Any) -> _Env:
        return _bind_into_next(caller_info, env, next_info)

    def detect_sink(
        self, sink_info: Any, env: _Env, dep_symbols: set[str]
    ) -> tuple[str, str] | None:
        parsed, fnode, _qual, _relpath = sink_info
        return _detect_sink(fnode, env, parsed, dep_symbols)
