"""Breadth-first JavaScript code analyzer built on tree-sitter.

This analyzer handles ``.js/.mjs/.cjs/.jsx`` files (JSX included). For every
file it emits, mirroring the Python analyzer's node/edge conventions:

* a ``module`` node (``mod:{relpath}`` -- JavaScript has no dotted module paths,
  so the repo-relative path is used as the module key) with a ``contains`` edge
  from the file node;
* ``function`` nodes (``fn:{relpath}:{qualname}``) with ``declares`` edges
  module -> function, for function declarations, named function/arrow
  expressions (``const f = () => {}`` / ``const f = function(){}``), class
  methods (qualname ``Class.method``) and object-literal method shorthand /
  function-valued properties (qualname ``objVar.method``). A function nested
  inside another is keyed by its enclosing qualname (``outer.inner``), so two
  same-named nested functions never collide into one id and a bare call cannot
  reach a nested function that is out of scope;
* ``imports`` edges module -> dependency for ES ``import ... from 'pkg'`` and
  CommonJS ``require('pkg')`` when a matching ``dep:npm:{name}`` node exists;
* ``calls`` edges from the enclosing function (or the module, for top-level
  code) to another function defined in the SAME file, or to a dependency via an
  imported binding (``attrs.symbol`` carries the resolved dotted name, e.g.
  ``lodash.merge``);
* ``entrypoint`` nodes and ``route_to_handler`` edges for Express/Koa/Fastify
  style routes (``app.get('/p', handler)``, ``router.post(...)`` ...).

==========================================================================
CROSS-FILE RESOLUTION (SOUND, opt-in through the shared repo_index)
==========================================================================

``scan.py`` builds a JavaScript export index BEFORE any analyzer runs: for every
``.js/.jsx/.mjs/.cjs`` file it calls :func:`index_source`, which returns that
file's EXPORTED-name -> function-id map. The maps are stored on ``repo_index``
under ``js_files`` (the set of repo-relative JS paths) and ``js_modules``
(module_relpath -> {export_name: fn_id}). This mirrors the Python analyzer's
``modules``/``functions`` index exactly; the Python keys are left untouched.

With that index, this analyzer resolves cross-file calls and route handlers --
but ONLY when both the module and the exported function are unambiguous:

* A RELATIVE specifier (``./x``, ``../util/y``) is resolved to a real repo file
  by trying ``x.js``/``x.jsx``/``x.mjs``/``x.cjs`` and ``x/index.*`` relative to
  the importing file's directory, against ``js_files``. A bare specifier
  (``lodash``, ``express``) is a package, not a cross-file target, and keeps the
  existing dependency-import behaviour. A relative specifier that does not match
  any repo file resolves to nothing -- no binding, no edge.
* ``const ctrl = require('./c')`` / ``import * as ctrl from './c'`` bind a
  cross-file NAMESPACE; ``ctrl.create()`` resolves to the single ``create``
  export of that module. ``const {create} = require('./c')`` /
  ``import {create} from './c'`` bind the export directly. ``import ctrl from
  './c'`` (default) binds the module's default export when it is a function.
* A route handler that is an imported binding (``app.post('/x', ctrl.create)``
  or ``app.post('/x', create)``) resolves to the cross-file ``fn:`` id by the
  same rules.

If the export name is absent or maps to more than one function, or the
specifier is dynamic/computed (``require(name)``) or does not resolve to a repo
file, the reference is recorded as unresolved and NO edge is emitted. A named
export is honoured only when its target is a function node this analyzer also
emits (a declaration, a ``const``-assigned function, a class/object method);
re-exports (``export ... from`` / ``module.exports = require(...)``) and
anonymous ``module.exports = function(){}`` values are NOT followed. Intra-file
points-to analysis remains out of scope.

==========================================================================
WHAT CALL/ROUTE RESOLUTION DOES AND DOES NOT HANDLE
==========================================================================

The CARDINAL RULE (shared with the Python analyzer): never emit a call, route
or import edge that cannot be resolved soundly. A wrong edge is worse than a
missing one for the reachability reasoning in later layers. Where a target
cannot be determined it is recorded as an ``unresolved_calls`` attribute on the
source function/module node rather than guessed.

RESOLVED
  * ``import x from 'pkg'`` / ``import * as x from 'pkg'`` /
    ``import {a, b as c} from 'pkg'`` -- the bound name maps to the dependency
    ``dep:npm:pkg`` (subpaths stripped, scoped packages kept whole).
  * ``const x = require('pkg')`` and ``const {a} = require('pkg')``.
  * Direct calls to a top-level function defined in the same file: ``f(...)``.
  * Attribute calls through an imported binding: ``_.merge(...)`` where
    ``const _ = require('lodash')`` -> dependency ``lodash`` with
    ``symbol=lodash.merge``.
  * Routes on a receiver that is an identifier whose NEAREST enclosing-scope
    binding is ``express()`` / ``Router()`` / ``express.Router()`` /
    ``new Koa()`` / ``Fastify()`` (the binding is resolved scope-aware, so an
    unrelated ``cache.get('key')`` or a same-named ``new Map()`` in a different
    function is never mistaken for a route).

NOT RESOLVED (recorded as ``unresolved_calls``, never guessed)
  * Method dispatch on an unknown object: ``obj.doThing()``, ``this.x()`` -- no
    type inference / points-to analysis is performed.
  * Calls through data structures, returns or dynamic names:
    ``handlers[key]()``, ``factory().run()``, ``obj[name]()``.
  * A name locally bound (parameter, local declaration, closed-over outer
    parameter/local, ``for..of``/``for..in`` binding, ``catch`` parameter) that
    shadows a module import never resolves through that import. The bound-name
    set for a call site is the UNION of every enclosing scope up the ancestor
    chain, so a closure or callback parameter correctly shadows. One-hop local
    aliasing of an import (resolved for Python) is NOT followed here -- recorded.
  * A bare call to a function that is not a module/top-level declaration (a
    nested or out-of-scope function); it is recorded, never guessed.
  * A relative import whose specifier does not resolve to a repo file, whose
    export name is absent or ambiguous, or which is dynamic/computed: no edge is
    fabricated -- the call/handler is recorded as unresolved.

Intra-file points-to analysis remains the clear future extension; the
``unresolved_calls`` records mark exactly where it plugs in.
"""

from __future__ import annotations

import posixpath
from typing import Any

from tree_sitter_language_pack import get_parser

from . import LanguageAnalyzer, register

# HTTP-method router call names -> HTTP verb. ``all`` maps to ``ANY`` (a
# method-less match, matching the Python analyzer's label) and ``use`` also maps
# to ``ANY`` but is additionally flagged as a mount (``attrs.mount=True``) when
# it carries a string path, so a middleware mount is distinguishable from a
# real HTTP endpoint. ``app.use(mw)`` without a string path is not an entry
# point at all (its first argument is not a literal path).
_ROUTE_METHODS: dict[str, str] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "options": "OPTIONS",
    "head": "HEAD",
    "all": "ANY",
    "use": "ANY",
}

# Constructor names that bind a variable to a web app / router, mapped to a
# framework label. A route call is only honoured when its receiver's nearest
# enclosing-scope binding is one of these (mirroring the Python analyzer's N10
# care), so that an unrelated ``x.get(...)`` / ``x.use(...)`` is not mistaken
# for an HTTP entry point. ``new Koa()`` is matched as a ``new`` expression.
_ROUTE_CONSTRUCTORS: dict[str, str] = {
    "express": "express",
    "Router": "express",
    "Koa": "koa",
    "Fastify": "fastify",
    "fastify": "fastify",
}

# Node types that open a new function scope (bind their own parameters).
_FUNCTION_TYPES: frozenset[str] = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)

# Sentinel distinguishing "name not bound in this scope" from "bound to a
# non-constructor" (which resolves to ``None``) in scope lookups.
_UNBOUND: Any = object()


def _node_text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def _string_literal_value(node: Any) -> str | None:
    """Return the value of a plain string-literal node, else ``None``.

    All ``string_fragment`` and ``escape_sequence`` children are concatenated
    (raw), so a multi-fragment literal such as ``"/a\\nb"`` is not truncated to
    its first fragment. Template strings and any non-``string`` node return
    ``None`` (not a static literal path), which keeps interpolated template
    paths unresolved.
    """
    if node is None or node.type != "string":
        return None
    parts: list[str] = []
    for child in node.children:
        if child.type in ("string_fragment", "escape_sequence"):
            parts.append(_node_text(child))
    # Empty string literal: ``''`` has no fragment child -> "".
    return "".join(parts)


def _normalize_specifier(spec: str) -> str | None:
    """Normalize an import/require specifier to an npm package name.

    ``lodash/fp`` -> ``lodash``; ``@scope/pkg/sub`` -> ``@scope/pkg``. Relative
    specifiers (``./x``, ``../y``) and absolute paths return ``None`` -- they are
    not packages and must not fabricate a dependency edge.
    """
    if not spec or spec.startswith(".") or spec.startswith("/"):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return spec
    return parts[0]


# Extensions tried when resolving an extension-less relative specifier, in the
# Node resolution order (file first, then ``<dir>/index.<ext>``).
_MODULE_SUFFIXES: tuple[str, ...] = (".js", ".jsx", ".mjs", ".cjs")


def _resolve_relative_module(
    spec: str, importer_relpath: str, js_files: set[str]
) -> str | None:
    """Resolve a relative specifier to a real repo JS file, or ``None``.

    ``spec`` is a relative specifier (``./x`` / ``../util/y``). It is joined to
    the importing file's directory and matched against ``js_files`` by trying
    ``x.js/.jsx/.mjs/.cjs`` and ``x/index.*``. Returns the matched repo-relative
    path, or ``None`` when nothing matches -- which keeps the import unresolved
    (no binding, no fabricated edge).
    """
    base_dir = posixpath.dirname(importer_relpath)
    target = posixpath.normpath(posixpath.join(base_dir, spec))
    candidates: list[str] = []
    if target.endswith(_MODULE_SUFFIXES):
        candidates.append(target)
    else:
        candidates.extend(target + suf for suf in _MODULE_SUFFIXES)
        candidates.extend(posixpath.join(target, "index" + suf) for suf in _MODULE_SUFFIXES)
    for cand in candidates:
        if cand in js_files:
            return cand
    return None


_INDEX_ANALYZER: Any = None


def index_source(relpath: str, source: str) -> tuple[str, dict[str, str]]:
    """Return ``(module_relpath, {export_name: fn_id})`` for one JS source file.

    Used by the orchestrator to build the cross-file export index before
    per-file analysis, so a call or route handler in one file can resolve into a
    function EXPORTED by another. The module key is the repo-relative path (the
    same key used for ``mod:{relpath}``). An export name is included ONLY when it
    maps to exactly one function node this analyzer also emits; ambiguous names,
    re-exports and anonymous ``module.exports = function(){}`` values are
    omitted (recorded as unresolved at the call site). Returns an empty map on a
    parse that yields no functions.
    """
    global _INDEX_ANALYZER
    if _INDEX_ANALYZER is None:
        _INDEX_ANALYZER = JavaScriptAnalyzer()
    analyzer = _INDEX_ANALYZER
    root = analyzer._get_parser().parse(source.encode("utf-8")).root_node
    functions = analyzer._collect_functions(root)
    top_level = {
        qual: f"fn:{relpath}:{qual}" for qual, _node, _body in functions if "." not in qual
    }
    exports = analyzer._collect_exports(root, top_level)
    return relpath, exports


@register
class JavaScriptAnalyzer(LanguageAnalyzer):
    """Breadth JavaScript analyzer. See the module docstring for the model."""

    language = "javascript"

    _parser: Any = None

    def _get_parser(self) -> Any:
        if JavaScriptAnalyzer._parser is None:
            JavaScriptAnalyzer._parser = get_parser("javascript")
        return JavaScriptAnalyzer._parser

    def analyze(
        self,
        file_node: Any,
        source: str,
        graph: Any,
        repo_index: dict[str, Any],
    ) -> None:
        relpath = file_node.attrs["relpath"]
        mod_id = f"mod:{relpath}"
        file_id = f"file:{relpath}"

        tree = self._get_parser().parse(source.encode("utf-8"))
        root = tree.root_node

        graph.add_node(mod_id, "module", relpath, relpath=relpath, language="javascript")
        graph.add_edge(file_id, mod_id, "contains")

        # 1. Imports -> symbol table (local name -> dependency descriptor) and
        #    dependency import edges.
        symtab = self._build_symbol_table(root, mod_id, graph, relpath, repo_index)

        # 2. Functions (+ declares edges). Nested functions are keyed by their
        #    enclosing qualname; ``local_functions`` holds only module/top-level
        #    declarations (the only names a bare call can reach soundly).
        functions = self._collect_functions(root)
        local_functions = {
            qual: f"fn:{relpath}:{qual}" for qual, _node, _body in functions if "." not in qual
        }
        for qual, fnode, _body in functions:
            fn_id = f"fn:{relpath}:{qual}"
            graph.add_node(
                fn_id,
                "function",
                qual,
                relpath=relpath,
                module=relpath,
                lineno=fnode.start_point[0] + 1,
                is_method="." in qual,
            )
            graph.add_edge(mod_id, fn_id, "declares")

        # 3. Call edges, attributed to the enclosing function (or the module).
        #    The bound-name set for each call site is computed from the UNION of
        #    all enclosing scopes (ancestor chain), so a shadowing closure or
        #    callback parameter keeps an import call unresolved.
        calls = self._collect_calls(root, functions)
        unresolved: dict[str, list[str]] = {}
        for enclosing, call in calls:
            src_id = mod_id if enclosing is None else f"fn:{relpath}:{enclosing}"
            bound = self._bound_names_at(call)
            result = self._resolve_call(call, symtab, bound, local_functions)
            kind = result[0]
            if kind == "fn":
                graph.add_edge(src_id, result[1], "calls")
            elif kind == "dep":
                graph.add_edge(src_id, result[1], "calls", symbol=result[2])
            elif kind == "skip":
                continue
            else:  # unresolved
                unresolved.setdefault(src_id, []).append(result[1])

        for src_id, reprs in unresolved.items():
            node = graph.get_node(src_id)
            if node is not None:
                node.attrs["unresolved_calls"] = sorted(set(reprs))[:50]
                node.attrs["unresolved_call_count"] = len(reprs)

        # 4. Entry points (routes).
        self._extract_routes(root, relpath, graph, symtab, local_functions)

    # -- imports / symbol table ----------------------------------------------

    def _build_symbol_table(
        self,
        root: Any,
        mod_id: str,
        graph: Any,
        relpath: str,
        repo_index: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Build ``{local_name: descriptor}`` and emit dependency ``imports`` edges.

        Descriptor types:
          * ``dep``        -- a package namespace binding (``import _ from
            'lodash'`` / ``const _ = require('lodash')``); ``base`` is the name.
          * ``dep_symbol`` -- a named package binding (``import {merge} from
            'lodash'`` / ``const {merge} = require('lodash')``); ``symbol`` is
            ``pkg.name``.
          * ``xmod``       -- a cross-file namespace binding (``import * as ns
            from './m'`` / ``const ns = require('./m')``); ``exports`` maps the
            module's export names to ``fn:`` ids, and ``default_fn`` is the
            default-export function id for a CommonJS namespace (``None`` for an
            ESM namespace, which is not callable).
          * ``xfn``        -- a direct cross-file function binding (``import
            {create} from './m'`` / ``const {create} = require('./m')`` /
            ``import create from './m'``); ``fn_id`` is the resolved function id.

        An ``imports`` edge is emitted only when a ``dep:npm:{pkg}`` node already
        exists in the graph (created by the manifest adapter). Relative imports
        bind cross-file descriptors but add no dependency edge.
        """
        symtab: dict[str, dict[str, Any]] = {}
        imported_pkgs: set[str] = set()

        def bind_namespace(local: str, pkg: str) -> None:
            dep_id = f"dep:npm:{pkg}"
            if graph.get_node(dep_id) is not None:
                symtab[local] = {"type": "dep", "dep_id": dep_id, "base": pkg}
            imported_pkgs.add(pkg)

        def bind_symbol(local: str, imported_name: str, pkg: str) -> None:
            dep_id = f"dep:npm:{pkg}"
            if graph.get_node(dep_id) is not None:
                symtab[local] = {
                    "type": "dep_symbol",
                    "dep_id": dep_id,
                    "symbol": f"{pkg}.{imported_name}",
                }
            imported_pkgs.add(pkg)

        def bind_xmod(local: str, exports: dict[str, str], default_fn: str | None) -> None:
            symtab[local] = {"type": "xmod", "exports": exports, "default_fn": default_fn}

        def bind_xfn(local: str, fn_id: str) -> None:
            symtab[local] = {"type": "xfn", "fn_id": fn_id}

        def walk(node: Any) -> None:
            if node.type == "import_statement":
                self._handle_import_statement(
                    node, bind_namespace, bind_symbol, bind_xmod, bind_xfn, relpath, repo_index
                )
            elif node.type == "variable_declarator":
                self._handle_require_declarator(
                    node, bind_namespace, bind_symbol, bind_xmod, bind_xfn, relpath, repo_index
                )
            for child in node.children:
                walk(child)

        walk(root)

        # Emit dependency import edges (one per package that resolved to a node).
        for pkg in sorted(imported_pkgs):
            dep_id = f"dep:npm:{pkg}"
            if graph.get_node(dep_id) is not None:
                graph.add_edge(mod_id, dep_id, "imports")

        return symtab

    def _handle_import_statement(
        self,
        node: Any,
        bind_namespace: Any,
        bind_symbol: Any,
        bind_xmod: Any,
        bind_xfn: Any,
        relpath: str,
        repo_index: dict[str, Any],
    ) -> None:
        # The specifier is the trailing string of the import statement.
        spec = None
        for child in node.children:
            if child.type == "string":
                spec = _string_literal_value(child)
        if spec is None:
            return
        if spec.startswith("."):
            self._handle_relative_import(node, spec, relpath, repo_index, bind_xmod, bind_xfn)
            return
        pkg = _normalize_specifier(spec)
        if pkg is None:
            return

        clause = None
        for child in node.children:
            if child.type == "import_clause":
                clause = child
                break
        if clause is None:
            # ``import 'pkg'`` (side-effect import): record the package so the
            # module->dep import edge is still emitted, but bind no name.
            bind_namespace("", pkg)
            return

        for part in clause.children:
            if part.type == "identifier":
                # Default import: ``import express from 'express'``.
                bind_namespace(_node_text(part), pkg)
            elif part.type == "namespace_import":
                # ``import * as _ from 'lodash'``.
                for sub in part.children:
                    if sub.type == "identifier":
                        bind_namespace(_node_text(sub), pkg)
            elif part.type == "named_imports":
                for spec_node in part.children:
                    if spec_node.type != "import_specifier":
                        continue
                    name_node = spec_node.child_by_field_name("name")
                    alias_node = spec_node.child_by_field_name("alias")
                    if name_node is None:
                        continue
                    imported = _node_text(name_node)
                    local = _node_text(alias_node) if alias_node is not None else imported
                    bind_symbol(local, imported, pkg)

    def _handle_relative_import(
        self,
        node: Any,
        spec: str,
        relpath: str,
        repo_index: dict[str, Any],
        bind_xmod: Any,
        bind_xfn: Any,
    ) -> None:
        """Bind cross-file descriptors for a resolved relative ESM import.

        A specifier that does not resolve to a repo file binds nothing (the
        reference stays unresolved). A named import whose export is absent or
        ambiguous binds nothing; a default import binds only when the module's
        default export is a function.
        """
        module_relpath = _resolve_relative_module(
            spec, relpath, repo_index.get("js_files", set())
        )
        if module_relpath is None:
            return
        exports: dict[str, str] = repo_index.get("js_modules", {}).get(module_relpath, {})
        default_fn = exports.get("default")

        clause = next((c for c in node.children if c.type == "import_clause"), None)
        if clause is None:
            return  # side-effect import ``import './m'``: no binding
        for part in clause.children:
            if part.type == "identifier":
                # Default import: binds to the module's default export function.
                if default_fn is not None:
                    bind_xfn(_node_text(part), default_fn)
            elif part.type == "namespace_import":
                for sub in part.children:
                    if sub.type == "identifier":
                        # ESM namespace is not callable -> no default_fn.
                        bind_xmod(_node_text(sub), exports, None)
            elif part.type == "named_imports":
                for spec_node in part.children:
                    if spec_node.type != "import_specifier":
                        continue
                    name_node = spec_node.child_by_field_name("name")
                    alias_node = spec_node.child_by_field_name("alias")
                    if name_node is None:
                        continue
                    imported = _node_text(name_node)
                    local = _node_text(alias_node) if alias_node is not None else imported
                    fn_id = exports.get(imported)
                    if fn_id is not None:
                        bind_xfn(local, fn_id)

    def _handle_require_declarator(
        self,
        node: Any,
        bind_namespace: Any,
        bind_symbol: Any,
        bind_xmod: Any,
        bind_xfn: Any,
        relpath: str,
        repo_index: dict[str, Any],
    ) -> None:
        value = node.child_by_field_name("value")
        if value is None or value.type != "call_expression":
            return
        callee = value.child_by_field_name("function")
        if callee is None or callee.type != "identifier" or _node_text(callee) != "require":
            return
        args = value.child_by_field_name("arguments")
        if args is None:
            return
        spec = None
        for arg in args.children:
            if arg.type == "string":
                spec = _string_literal_value(arg)
                break
        if spec is None:
            # Dynamic/computed require (``require(name)``): unresolvable, bind
            # nothing so any call through the binding stays unresolved.
            return
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return

        if spec.startswith("."):
            self._handle_relative_require(name_node, spec, relpath, repo_index, bind_xmod, bind_xfn)
            return

        pkg = _normalize_specifier(spec)
        if pkg is None:
            return
        if name_node.type == "identifier":
            bind_namespace(_node_text(name_node), pkg)
        elif name_node.type == "object_pattern":
            # ``const { merge } = require('lodash')`` / ``{ merge: m }``.
            for part in name_node.children:
                if part.type == "shorthand_property_identifier_pattern":
                    sym = _node_text(part)
                    bind_symbol(sym, sym, pkg)
                elif part.type == "pair_pattern":
                    key = part.child_by_field_name("key")
                    val = part.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        bind_symbol(_node_text(val), _node_text(key), pkg)

    def _handle_relative_require(
        self,
        name_node: Any,
        spec: str,
        relpath: str,
        repo_index: dict[str, Any],
        bind_xmod: Any,
        bind_xfn: Any,
    ) -> None:
        """Bind cross-file descriptors for a resolved relative CommonJS require.

        ``const ns = require('./m')`` binds a namespace (``ns.member`` resolves,
        and a bare ``ns()`` resolves when the module default-exports a function);
        ``const { create } = require('./m')`` binds each export that resolves to
        exactly one function. Unresolved specifiers/exports bind nothing.
        """
        module_relpath = _resolve_relative_module(
            spec, relpath, repo_index.get("js_files", set())
        )
        if module_relpath is None:
            return
        exports: dict[str, str] = repo_index.get("js_modules", {}).get(module_relpath, {})
        if name_node.type == "identifier":
            bind_xmod(_node_text(name_node), exports, exports.get("default"))
        elif name_node.type == "object_pattern":
            for part in name_node.children:
                if part.type == "shorthand_property_identifier_pattern":
                    sym = _node_text(part)
                    fn_id = exports.get(sym)
                    if fn_id is not None:
                        bind_xfn(sym, fn_id)
                elif part.type == "pair_pattern":
                    key = part.child_by_field_name("key")
                    val = part.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        fn_id = exports.get(_node_text(key))
                        if fn_id is not None:
                            bind_xfn(_node_text(val), fn_id)

    # -- function discovery ---------------------------------------------------

    def _collect_functions(self, root: Any) -> list[tuple[str, Any, Any]]:
        """Return ``(qualname, function_node, body_node)`` for every function.

        Covers function declarations, named function/arrow expressions assigned
        to a ``const``/``let``/``var``, class methods (``Class.method``) and
        object-literal method shorthand / function-valued properties
        (``objVar.method``). A function nested inside another carries its
        enclosing qualname as a prefix (``outer.inner``), so distinct nested
        functions never share an id.
        """
        functions: list[tuple[str, Any, Any]] = []

        def record(qual: str, fnode: Any) -> None:
            body = fnode.child_by_field_name("body")
            functions.append((qual, fnode, body))

        def descend_body(body: Any, prefix: str) -> None:
            if body is None:
                return
            for c in body.children:
                visit(c, prefix)

        def visit(node: Any, prefix: str) -> None:
            t = node.type
            if t in ("function_declaration", "generator_function_declaration"):
                name = node.child_by_field_name("name")
                qual = (prefix + _node_text(name)) if name is not None else None
                if qual is not None:
                    record(qual, node)
                descend_body(
                    node.child_by_field_name("body"),
                    (qual + ".") if qual is not None else prefix,
                )
                return
            if t == "class_declaration":
                cname = node.child_by_field_name("name")
                body = node.child_by_field_name("body")
                class_prefix = (prefix + _node_text(cname) + ".") if cname is not None else prefix
                if body is not None:
                    for member in body.children:
                        if member.type == "method_definition":
                            mname = member.child_by_field_name("name")
                            mqual = (
                                (class_prefix + _node_text(mname)) if mname is not None else None
                            )
                            if mqual is not None:
                                record(mqual, member)
                            descend_body(
                                member.child_by_field_name("body"),
                                (mqual + ".") if mqual is not None else class_prefix,
                            )
                        else:
                            visit(member, prefix)
                return
            if t == "variable_declarator":
                if self._visit_declarator(node, prefix, record, descend_body, visit):
                    return
            for child in node.children:
                visit(child, prefix)

        visit(root, "")
        return functions

    def _visit_declarator(
        self, node: Any, prefix: str, record: Any, descend_body: Any, visit: Any
    ) -> bool:
        """Handle ``const name = <fn|object>``. Returns True if fully handled."""
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None or name_node.type != "identifier":
            return False
        var = _node_text(name_node)

        if value.type in ("arrow_function", "function_expression", "generator_function"):
            qual = prefix + var
            record(qual, value)
            descend_body(value.child_by_field_name("body"), qual + ".")
            return True

        if value.type == "object":
            for member in value.children:
                if member.type == "method_definition":
                    mname = member.child_by_field_name("name")
                    mqual = (f"{prefix}{var}.{_node_text(mname)}") if mname is not None else None
                    if mqual is not None:
                        record(mqual, member)
                    descend_body(
                        member.child_by_field_name("body"),
                        (mqual + ".") if mqual is not None else prefix,
                    )
                elif member.type == "pair":
                    pval = member.child_by_field_name("value")
                    key = member.child_by_field_name("key")
                    if (
                        pval is not None
                        and key is not None
                        and pval.type in ("arrow_function", "function_expression", "generator_function")
                    ):
                        mqual = f"{prefix}{var}.{_node_text(key)}"
                        record(mqual, pval)
                        descend_body(pval.child_by_field_name("body"), mqual + ".")
                    else:
                        visit(member, prefix)
                else:
                    visit(member, prefix)
            return True

        return False

    # -- exports (cross-file index) -------------------------------------------

    def _collect_exports(
        self, root: Any, top_level: dict[str, str]
    ) -> dict[str, str]:
        """Map each EXPORTED name to the single function id it refers to.

        ``top_level`` maps a module/top-level function qualname to its ``fn:``
        id. An export resolves only to a name present there, so the target is
        always a real function node. Names that would map to more than one
        distinct function id are dropped (ambiguous -> unresolved), honouring the
        cardinal rule.
        """
        candidates: dict[str, set[str]] = {}

        def add(name: str | None, fn_id: str | None) -> None:
            if name and fn_id:
                candidates.setdefault(name, set()).add(fn_id)

        def walk(node: Any) -> None:
            if node.type == "export_statement":
                self._collect_export_statement(node, top_level, add)
            elif node.type == "assignment_expression":
                self._collect_cjs_export(node, top_level, add)
            for child in node.children:
                walk(child)

        walk(root)
        return {name: next(iter(ids)) for name, ids in candidates.items() if len(ids) == 1}

    def _collect_export_statement(
        self, node: Any, top_level: dict[str, str], add: Any
    ) -> None:
        # Re-export (``export { x } from './y'``): cannot be followed soundly.
        if node.child_by_field_name("source") is not None:
            return
        is_default = any(c.type == "default" for c in node.children)
        decl = node.child_by_field_name("declaration")
        if decl is not None:
            if decl.type in ("function_declaration", "generator_function_declaration"):
                name_node = decl.child_by_field_name("name")
                if name_node is not None:
                    local = _node_text(name_node)
                    add("default" if is_default else local, top_level.get(local))
            elif decl.type in ("lexical_declaration", "variable_declaration"):
                for d in decl.children:
                    if d.type != "variable_declarator":
                        continue
                    nn = d.child_by_field_name("name")
                    if nn is not None and nn.type == "identifier":
                        local = _node_text(nn)
                        add("default" if is_default else local, top_level.get(local))
            return
        if is_default:
            # ``export default <expr>``: only an identifier naming a top-level
            # function is followed; anonymous expressions/objects are not.
            for child in node.children:
                if child.type == "identifier":
                    add("default", top_level.get(_node_text(child)))
            return
        clause = next((c for c in node.children if c.type == "export_clause"), None)
        if clause is None:
            return
        for spec_node in clause.children:
            if spec_node.type != "export_specifier":
                continue
            name_node = spec_node.child_by_field_name("name")
            alias_node = spec_node.child_by_field_name("alias")
            if name_node is None:
                continue
            local = _node_text(name_node)
            exported = _node_text(alias_node) if alias_node is not None else local
            add(exported, top_level.get(local))

    def _collect_cjs_export(
        self, node: Any, top_level: dict[str, str], add: Any
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "member_expression":
            return
        root, attrs = self._flatten_ref(left)
        if root == "module" and attrs == ["exports"]:
            if right is not None and right.type == "object":
                self._collect_exports_object(right, top_level, add)
            elif right is not None and right.type == "identifier":
                add("default", top_level.get(_node_text(right)))
        elif root == "exports" and len(attrs) == 1:
            if right is not None and right.type == "identifier":
                add(attrs[0], top_level.get(_node_text(right)))
        elif root == "module" and len(attrs) == 2 and attrs[0] == "exports":
            if right is not None and right.type == "identifier":
                add(attrs[1], top_level.get(_node_text(right)))

    def _collect_exports_object(
        self, obj: Any, top_level: dict[str, str], add: Any
    ) -> None:
        for member in obj.children:
            if member.type == "shorthand_property_identifier":
                name = _node_text(member)
                add(name, top_level.get(name))
            elif member.type == "pair":
                key = member.child_by_field_name("key")
                value = member.child_by_field_name("value")
                if key is not None and value is not None and value.type == "identifier":
                    add(_node_text(key), top_level.get(_node_text(value)))

    # -- scope (bound names up the ancestor chain, for shadowing) -------------

    def _bound_names_at(self, call_node: Any) -> set[str]:
        """Names bound in ANY scope enclosing ``call_node``.

        Walks ``parent`` to the root, collecting: the formal parameters of every
        enclosing function/method (and an arrow's single unparenthesised
        parameter), each ``catch`` parameter, each ``for..of``/``for..in``
        binding, and the ``let``/``const``/``var`` and nested function/class
        declarations of every enclosing ``statement_block`` (and ``for``
        initializer). Module/top-level (``program``) declarations are NOT
        collected -- they are the module scope that the import symbol table
        already represents, so they must not shadow themselves. A name in this
        set shadows a module import, so a call through it stays unresolved
        rather than producing a false dependency edge.
        """
        bound: set[str] = set()
        cur = call_node.parent
        while cur is not None:
            t = cur.type
            if t in _FUNCTION_TYPES:
                self._collect_function_params(cur, bound)
            elif t == "catch_clause":
                self._collect_binding(cur.child_by_field_name("parameter"), bound)
            elif t == "for_in_statement":
                self._collect_binding(cur.child_by_field_name("left"), bound)
            elif t == "for_statement":
                init = cur.child_by_field_name("initializer")
                if init is not None and init.type in ("lexical_declaration", "variable_declaration"):
                    self._collect_decl_names(init, bound)
            if t == "statement_block":
                self._collect_block_declarations(cur, bound)
            cur = cur.parent
        return bound

    def _collect_function_params(self, fnode: Any, bound: set[str]) -> None:
        params = fnode.child_by_field_name("parameters")
        if params is not None:
            self._collect_pattern_identifiers(params, bound)
        single = fnode.child_by_field_name("parameter")
        if single is not None and single.type == "identifier":
            # Arrow with a single un-parenthesised parameter: ``x => ...``.
            bound.add(_node_text(single))

    def _collect_binding(self, node: Any, bound: set[str]) -> None:
        """Collect a single binding target (identifier or destructuring pattern)."""
        if node is None:
            return
        if node.type == "identifier":
            bound.add(_node_text(node))
        else:
            self._collect_pattern_identifiers(node, bound)

    def _collect_pattern_identifiers(self, node: Any, bound: set[str]) -> None:
        """Collect bare identifiers bound by a parameter/destructuring pattern."""
        for child in node.children:
            if child.type == "identifier":
                bound.add(_node_text(child))
            elif child.type in ("shorthand_property_identifier_pattern",):
                bound.add(_node_text(child))
            elif child.type in (
                "required_parameter",
                "optional_parameter",
                "object_pattern",
                "array_pattern",
                "rest_pattern",
                "assignment_pattern",
                "object_assignment_pattern",
                "pair_pattern",
            ):
                self._collect_pattern_identifiers(child, bound)

    def _collect_block_declarations(self, block: Any, bound: set[str]) -> None:
        """Collect the direct declarations of one statement block (no descent)."""
        for child in block.children:
            t = child.type
            if t in ("lexical_declaration", "variable_declaration"):
                self._collect_decl_names(child, bound)
            elif t in (
                "function_declaration",
                "generator_function_declaration",
                "class_declaration",
            ):
                name = child.child_by_field_name("name")
                if name is not None:
                    bound.add(_node_text(name))

    def _collect_decl_names(self, decl: Any, bound: set[str]) -> None:
        """Collect the names bound by a single ``let``/``const``/``var``."""
        for d in decl.children:
            if d.type != "variable_declarator":
                continue
            name_node = d.child_by_field_name("name")
            if name_node is None:
                continue
            if name_node.type == "identifier":
                bound.add(_node_text(name_node))
            else:
                self._collect_pattern_identifiers(name_node, bound)

    # -- call discovery + resolution ------------------------------------------

    def _collect_calls(
        self, root: Any, functions: list[tuple[str, Any, Any]]
    ) -> list[tuple[str | None, Any]]:
        """Return ``(enclosing_qualname_or_None, call_node)`` for every call.

        A call is attributed to the nearest enclosing *named* function; calls at
        module level (and inside anonymous functions not bound to a name) are
        attributed to the module (``enclosing=None``). ``require(...)`` calls are
        excluded (handled by the symbol table).
        """
        # Map a function's body node id -> its qualname, to switch enclosing when
        # descending into that body.
        body_owner: dict[int, str] = {}
        for qual, _fnode, body in functions:
            if body is not None:
                body_owner[body.id] = qual

        calls: list[tuple[str | None, Any]] = []

        def visit(node: Any, enclosing: str | None) -> None:
            owner = body_owner.get(node.id)
            current = owner if owner is not None else enclosing
            if node.type == "call_expression":
                callee = node.child_by_field_name("function")
                if not (
                    callee is not None
                    and callee.type == "identifier"
                    and _node_text(callee) == "require"
                ):
                    calls.append((current, node))
            for child in node.children:
                visit(child, current)

        visit(root, None)
        return calls

    def _flatten_ref(self, node: Any) -> tuple[str | None, list[str]]:
        """Flatten an identifier or member chain into ``(root, [attr, ...])``.

        Returns ``(None, [])`` for anything that is not an identifier or a member
        chain rooted at an identifier (e.g. ``this.x``, ``obj[k]``, ``f().x``) --
        such references are unresolvable.
        """
        if node is None:
            return (None, [])
        if node.type == "identifier":
            return (_node_text(node), [])
        if node.type == "member_expression":
            attrs: list[str] = []
            cur = node
            while cur is not None and cur.type == "member_expression":
                prop = cur.child_by_field_name("property")
                if prop is None or prop.type != "property_identifier":
                    return (None, [])
                attrs.append(_node_text(prop))
                cur = cur.child_by_field_name("object")
            attrs.reverse()
            if cur is not None and cur.type == "identifier":
                return (_node_text(cur), attrs)
            return (None, [])
        return (None, [])

    def _callee_root_and_attrs(self, call: Any) -> tuple[str | None, list[str]]:
        """Flatten a call's callee into ``(root_identifier, [attr, ...])``.

        Returns ``(None, [])`` when the callee is not an identifier or a member
        chain rooted at an identifier (e.g. ``this.x()``, ``obj[k]()``,
        ``f()()``) -- such calls are unresolvable.
        """
        return self._flatten_ref(call.child_by_field_name("function"))

    def _resolve_call(
        self,
        call: Any,
        symtab: dict[str, dict[str, Any]],
        bound: set[str],
        local_functions: dict[str, str],
    ) -> tuple[str, ...]:
        root, attrs = self._callee_root_and_attrs(call)
        if root is None:
            return ("unresolved", self._safe_call_repr(call))

        unresolved_repr = root if not attrs else root + "." + ".".join(attrs)

        # A locally-bound name shadows any module import. One-hop local aliasing
        # (followed for Python) is not resolved here: record, never guess.
        if root in bound:
            return ("unresolved", unresolved_repr)

        if root in symtab:
            desc = symtab[root]
            dtype = desc["type"]
            suffix = ("." + ".".join(attrs)) if attrs else ""
            if dtype == "dep":
                return ("dep", desc["dep_id"], desc["base"] + suffix)
            if dtype == "dep_symbol":
                return ("dep", desc["dep_id"], desc["symbol"] + suffix)
            if dtype in ("xmod", "xfn"):
                fn_id = self._resolve_ref_to_fn(root, attrs, symtab, local_functions)
                if fn_id is not None:
                    return ("fn", fn_id)
                return ("unresolved", unresolved_repr)

        if not attrs and root in local_functions:
            return ("fn", local_functions[root])

        return ("unresolved", unresolved_repr)

    def _resolve_ref_to_fn(
        self,
        root: str,
        attrs: list[str],
        symtab: dict[str, dict[str, Any]],
        local_functions: dict[str, str],
    ) -> str | None:
        """Resolve a flattened reference to a single ``fn:`` id, else ``None``.

        Handles cross-file namespace (``xmod``: ``ns.member`` or, for a CommonJS
        namespace whose module exports a default function, a bare call) and
        direct cross-file bindings (``xfn``), plus same-file top-level functions.
        A dependency binding is never a function handler, so it returns ``None``.
        Returns ``None`` whenever the reference is ambiguous or out of scope --
        no edge is then emitted.
        """
        if root in symtab:
            desc = symtab[root]
            dtype = desc["type"]
            if dtype == "xmod":
                if len(attrs) == 1:
                    return desc["exports"].get(attrs[0])
                if not attrs:
                    return desc.get("default_fn")
                return None
            if dtype == "xfn":
                return desc["fn_id"] if not attrs else None
            return None  # dep / dep_symbol: not a local function
        if not attrs and root in local_functions:
            return local_functions[root]
        return None

    @staticmethod
    def _safe_call_repr(call: Any) -> str:
        func = call.child_by_field_name("function")
        if func is None:
            return "<call>"
        text = _node_text(func)
        return text[:80] if text else "<call>"

    # -- entry points (routes) ------------------------------------------------

    def _receiver_framework(
        self, receiver_node: Any, symtab: dict[str, dict[str, Any]]
    ) -> str | None:
        """Resolve a route-call receiver identifier to a framework label, or None.

        Walks the enclosing scopes outward from the call site. The NEAREST
        binding of the receiver name decides: a function/``catch``/``for`` binding
        of the name means it is a parameter or loop/exception variable (not a
        router); a ``let``/``const``/``var`` or assignment binding resolves to a
        framework only when its value is a web-app/router constructor
        (``express()`` / ``Router()`` / ``new Koa()`` ...). A name bound to any
        other value (e.g. ``new Map()``), or never bound in the file, is not a
        router -- so no false entry point is emitted.
        """
        name = _node_text(receiver_node)
        cur = receiver_node.parent
        while cur is not None:
            t = cur.type
            if t in _FUNCTION_TYPES:
                params: set[str] = set()
                self._collect_function_params(cur, params)
                if name in params:
                    return None
            elif t == "catch_clause":
                b: set[str] = set()
                self._collect_binding(cur.child_by_field_name("parameter"), b)
                if name in b:
                    return None
            elif t == "for_in_statement":
                b2: set[str] = set()
                self._collect_binding(cur.child_by_field_name("left"), b2)
                if name in b2:
                    return None
            if t in ("statement_block", "program"):
                framework = self._scope_binding_framework(cur, name, symtab)
                if framework is not _UNBOUND:
                    return framework
            cur = cur.parent
        return None

    def _scope_binding_framework(
        self, scope_node: Any, name: str, symtab: dict[str, dict[str, Any]]
    ) -> Any:
        """Framework for the binding of ``name`` directly in ``scope_node``.

        Returns ``_UNBOUND`` when the name is not bound here (keep walking
        outward), a framework string when bound to a known constructor, or
        ``None`` when bound to a non-constructor value (so the receiver is not a
        router). The last binding wins within one scope (conservative).
        """
        result: Any = _UNBOUND
        for child in scope_node.children:
            if child.type in ("lexical_declaration", "variable_declaration"):
                for d in child.children:
                    if d.type != "variable_declarator":
                        continue
                    nn = d.child_by_field_name("name")
                    if nn is not None and nn.type == "identifier" and _node_text(nn) == name:
                        result = self._value_framework(d.child_by_field_name("value"), symtab)
            elif child.type == "expression_statement":
                for sub in child.children:
                    if sub.type != "assignment_expression":
                        continue
                    left = sub.child_by_field_name("left")
                    if left is not None and left.type == "identifier" and _node_text(left) == name:
                        result = self._value_framework(sub.child_by_field_name("right"), symtab)
        return result

    def _value_framework(
        self, value: Any, symtab: dict[str, dict[str, Any]]
    ) -> str | None:
        """Framework label if ``value`` constructs a web app/router, else None."""
        if value is None:
            return None
        if value.type == "call_expression":
            return self._constructor_framework(value, symtab)
        if value.type == "new_expression":
            ctor = value.child_by_field_name("constructor")
            if ctor is None:
                return None
            cname: str | None = None
            if ctor.type == "identifier":
                cname = _node_text(ctor)
            elif ctor.type == "member_expression":
                prop = ctor.child_by_field_name("property")
                if prop is not None and prop.type == "property_identifier":
                    cname = _node_text(prop)
            if cname is not None:
                return _ROUTE_CONSTRUCTORS.get(cname)
        return None

    def _constructor_framework(
        self, call: Any, symtab: dict[str, dict[str, Any]]
    ) -> str | None:
        callee = call.child_by_field_name("function")
        if callee is None:
            return None
        cname: str | None = None
        if callee.type == "identifier":
            cname = _node_text(callee)
        elif callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            if prop is not None and prop.type == "property_identifier":
                cname = _node_text(prop)
        if cname is None:
            return None
        return _ROUTE_CONSTRUCTORS.get(cname)

    def _extract_routes(
        self,
        root: Any,
        relpath: str,
        graph: Any,
        symtab: dict[str, dict[str, Any]],
        local_functions: dict[str, str],
    ) -> None:
        def walk(node: Any) -> None:
            if node.type == "call_expression":
                self._maybe_route(node, relpath, graph, symtab, local_functions)
            for child in node.children:
                walk(child)

        walk(root)

    def _maybe_route(
        self,
        call: Any,
        relpath: str,
        graph: Any,
        symtab: dict[str, dict[str, Any]],
        local_functions: dict[str, str],
    ) -> None:
        callee = call.child_by_field_name("function")
        if callee is None or callee.type != "member_expression":
            return
        receiver = callee.child_by_field_name("object")
        prop = callee.child_by_field_name("property")
        if (
            receiver is None
            or receiver.type != "identifier"
            or prop is None
            or prop.type != "property_identifier"
        ):
            return
        prop_name = _node_text(prop).lower()
        method = _ROUTE_METHODS.get(prop_name)
        if method is None:
            return
        framework = self._receiver_framework(receiver, symtab)
        if framework is None:
            return

        args = call.child_by_field_name("arguments")
        if args is None:
            return
        arg_exprs = [c for c in args.children if c.is_named]
        if not arg_exprs:
            return
        path = _string_literal_value(arg_exprs[0])
        if path is None:
            return  # first argument must be a string-literal path

        is_mount = prop_name == "use"
        ep_id = f"ep:{method}:{path}"
        handler_node = arg_exprs[-1] if len(arg_exprs) > 1 else None

        bound = self._bound_names_at(call)
        handler_kind, handler_repr, handler_fn_id = self._classify_handler(
            handler_node, local_functions, bound, symtab
        )

        existing = graph.get_node(ep_id)
        if existing is not None:
            # Id collision: keep the first handler, never overwrite it. Record
            # any additional resolved handler so the clash is visible.
            if handler_fn_id is not None and (
                existing.attrs.get("handler") != handler_repr
                or existing.attrs.get("handler_file") != relpath
            ):
                collisions = existing.attrs.setdefault("handler_collisions", [])
                entry = {"handler": handler_repr, "handler_file": relpath}
                if entry not in collisions:
                    collisions.append(entry)
            if handler_fn_id is not None:
                graph.add_edge(ep_id, handler_fn_id, "route_to_handler")
            return

        attrs: dict[str, Any] = {
            "method": method,
            "path": path,
            "framework": framework,
        }
        if is_mount:
            attrs["mount"] = True
        if handler_kind == "named":
            attrs["handler"] = handler_repr
            attrs["handler_file"] = relpath
        elif handler_kind == "inline":
            attrs["inline_handler"] = True
        elif handler_kind == "unresolved":
            attrs["unresolved_handler"] = handler_repr
        graph.add_node(ep_id, "entrypoint", f"{method} {path}", **attrs)
        if handler_fn_id is not None:
            graph.add_edge(ep_id, handler_fn_id, "route_to_handler")

    def _classify_handler(
        self,
        handler_node: Any,
        local_functions: dict[str, str],
        bound: set[str],
        symtab: dict[str, dict[str, Any]],
    ) -> tuple[str, str | None, str | None]:
        """Return ``(kind, handler_repr, fn_id_or_None)`` for a route handler.

        A reference that resolves to exactly one function -- a module/top-level
        function in this file, or an unambiguous cross-file export reached
        through an imported binding (``create`` / ``ctrl.create``) -- yields an
        edge. An inline anonymous function is flagged with no edge. A name that
        is locally bound (a parameter/local that shadows the function), a
        dependency call, or an otherwise-unresolvable reference is recorded as an
        unresolved handler with no fabricated ``fn:`` edge.
        """
        if handler_node is None:
            return ("none", None, None)
        root, attrs = self._flatten_ref(handler_node)
        if root is not None:
            repr_ = root if not attrs else root + "." + ".".join(attrs)
            if root in bound:
                # Parameter/local shadow: NOT the import/top-level of that name.
                return ("unresolved", repr_, None)
            fn_id = self._resolve_ref_to_fn(root, attrs, symtab, local_functions)
            if fn_id is not None:
                return ("named", repr_, fn_id)
            return ("unresolved", repr_, None)
        if handler_node.type in ("arrow_function", "function_expression", "generator_function"):
            return ("inline", None, None)
        # Call, index access, etc.: record its text, fabricate no edge.
        return ("unresolved", _node_text(handler_node)[:80], None)
