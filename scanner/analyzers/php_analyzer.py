"""PHP code analyzer built on tree-sitter (``tree_sitter_language_pack``).

For every ``.php`` file this emits, mirroring the shape of the Python analyzer:

* a ``module`` node (id ``mod:{relpath}``) and ``function`` nodes (methods carry
  a qualified name ``ClassName.method``, matching the Python analyzer's dotted
  method style), with ``declares`` edges module -> function and a ``contains``
  edge file -> module;
* module-level import *records* for ``use`` statements (see IMPORTS below);
* ``calls`` edges from the enclosing function to another function/method defined
  in the SAME file;
* ``entrypoint`` nodes and ``route_to_handler`` edges for web routes
  (Laravel ``Route::verb``, Slim ``$app->verb``, Symfony ``#[Route]`` attrs).

==========================================================================
SINGLE-FILE SCOPE  (the boundary for later layers)
==========================================================================

This analysis is deliberately **single-file**. ``scan.py`` builds its cross-file
``repo_index`` from Python files only, so it contains nothing for PHP; no attempt
is made to resolve a call, import, or route handler into another PHP file.
Cross-file PHP resolution (autoloading, namespace -> file mapping, inheritance
across files) is out of scope and is never fabricated.

==========================================================================
WHAT CALL RESOLUTION DOES AND DOES NOT HANDLE
==========================================================================

tree-sitter gives an exact parse; name *binding* is resolved with a shallow,
conservative model. Where a target cannot be determined soundly the call is
recorded in an ``unresolved_calls`` list attribute on the source node rather than
guessed -- a wrong edge is worse than a missing one for reachability reasoning.
PHP's dynamic nature means a large fraction of calls stay unresolved; that is
correct behaviour, not a shortcoming.

RESOLVED (intra-file only)
  * ``helper(...)`` -- a direct call to a top-level ``function`` defined in this
    file.
  * ``$this->m(...)`` / ``self::m(...)`` / ``static::m(...)`` -- dispatch to a
    method ``m`` DEFINED in the enclosing class in this same file. This is the
    one place resolution goes beyond pure name binding: it is sound because the
    locally-defined method is a genuine, reachable call target on ``$this`` (and
    under late static binding on ``static``), which is exactly what the task's
    intra-class call edge requires.
  * ``ClassName::m(...)`` -- a static call where ``ClassName`` is a class defined
    in this same file and ``m`` is one of its methods.

NOT RESOLVED (recorded, never guessed)
  * Method dispatch on any other object: ``$service->run()``, ``$obj->m()`` --
    no type inference / points-to analysis is performed.
  * ``parent::m()`` -- the parent class is not necessarily in this file.
  * Calls to functions/classes not defined in this file (e.g. framework or
    vendor code, PHP built-ins), namespaced calls, dynamic/variable calls
    (``$fn()``, ``call_user_func(...)``, ``$obj->$name()``).

==========================================================================
IMPORTS (``use`` statements) -- intentionally conservative
==========================================================================

A PHP namespace (``use GuzzleHttp\\Client;``) does NOT map reliably to a Composer
package name (``guzzlehttp/guzzle``): the mapping lives in the autoload config,
not the namespace. Guessing a ``dep:Packagist:*`` edge from a namespace would
routinely be wrong, so this analyzer does NOT do it. Every ``use`` is recorded
as a module-level import record in the module node's ``imports`` attribute, and
an ``imports`` edge to a dependency is emitted ONLY when a package can be mapped
with real confidence (which, from a bare namespace, it cannot). It is therefore
expected and honest for this analyzer to produce zero dependency import edges.
"""

from __future__ import annotations

from typing import Any

from tree_sitter_language_pack import get_parser

from . import LanguageAnalyzer, register

# HTTP-verb method names (Laravel facade / Slim app) -> HTTP verb.
_HTTP_VERBS: dict[str, str] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "head": "HEAD",
    "options": "OPTIONS",
}

# Node types whose body may contain methods we treat as functions.
_CLASSLIKE: frozenset[str] = frozenset(
    {
        "class_declaration",
        "trait_declaration",
        "enum_declaration",
        "interface_declaration",
    }
)

# Relative scopes (``scope::``) that refer to the enclosing class in this file.
# ``parent`` is excluded: the parent class is not necessarily in this file.
_SELF_SCOPES: frozenset[str] = frozenset({"self", "static"})


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def _named_children(node: Any) -> list[Any]:
    return [c for c in node.children if c.is_named]


@register
class PhpAnalyzer(LanguageAnalyzer):
    """PHP analyzer. See the module docstring for the resolution model."""

    language = "php"

    # Lazily-created, shared PHP parser. Constructing it is relatively expensive
    # and can fail if the grammar is unavailable; building it on first use (not
    # at import time) keeps an import of ``scanner.analyzers`` -- and therefore
    # the rest of the scanner, including the Python analyzer -- alive even when
    # the PHP grammar cannot be loaded.
    _parser: Any = None

    def _get_parser(self) -> Any:
        if PhpAnalyzer._parser is None:
            PhpAnalyzer._parser = get_parser("php")
        return PhpAnalyzer._parser

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

        imports = self._collect_imports(root)
        graph.add_node(
            mod_id,
            "module",
            relpath,
            relpath=relpath,
            imports=imports,
        )
        graph.add_edge(file_id, mod_id, "contains")

        functions, calls = self._collect(root)
        # qualname -> owning class name (None for a top-level function).
        local_quals = {qual for qual, _, _, _ in functions}
        # class name -> set of method names defined in that class in this file.
        # Abstract/interface methods (no body) are NOT recorded here: they are
        # never a sound call target -- the real implementation lives in a
        # subclass, which is another file and out of scope. Resolving
        # ``$this->run()`` or ``I::m()`` to a bodiless declaration would be a
        # false edge.
        class_methods: dict[str, set[str]] = {}
        for qual, _node, cls, abstract in functions:
            if cls is not None and not abstract:
                method = qual.split(".", 1)[1]
                class_methods.setdefault(cls, set()).add(method)

        # Function nodes + declares edges.
        for qual, fnode, _cls, abstract in functions:
            fn_id = f"fn:{relpath}:{qual}"
            attrs: dict[str, Any] = {
                "relpath": relpath,
                "module": relpath,
                "lineno": fnode.start_point[0] + 1,
                "is_method": "." in qual,
            }
            if abstract:
                # Emitted so the declaration is visible, but marked so later
                # layers know it is not itself a reachable call target.
                attrs["abstract"] = True
            graph.add_node(fn_id, "function", qual, **attrs)
            graph.add_edge(mod_id, fn_id, "declares")

        # Call edges.
        unresolved: dict[str, list[str]] = {}
        for enclosing, enclosing_class, call in calls:
            src_id = mod_id if enclosing is None else f"fn:{relpath}:{enclosing}"
            resolved = self._resolve_call(
                call, enclosing_class, local_quals, class_methods
            )
            kind = resolved[0]
            if kind == "fn":
                graph.add_edge(src_id, f"fn:{relpath}:{resolved[1]}", "calls")
            else:  # unresolved
                unresolved.setdefault(src_id, []).append(resolved[1])

        for src_id, reprs in unresolved.items():
            node = graph.get_node(src_id)
            if node is not None:
                node.attrs["unresolved_calls"] = sorted(set(reprs))[:50]
                node.attrs["unresolved_call_count"] = len(reprs)

        # Entry points (routes).
        self._extract_routes(root, relpath, local_quals, imports, graph)

    # -- imports --------------------------------------------------------------

    def _collect_imports(self, root: Any) -> list[str]:
        """Return the fully-qualified names of every ``use`` import.

        Conservative by design: no ``dep:`` edge is derived from a namespace
        (see the module docstring). Grouped uses (``use A\\{B, C};``) and aliases
        (``use A\\B as C;``) are flattened to their qualified names.
        """
        imports: list[str] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "namespace_use_declaration":
                prefix = ""
                for child in node.children:
                    if child.type == "namespace_name":
                        # Group use: ``use Prefix\{A, B};``.
                        prefix = _text(child) + "\\"
                    elif child.type == "namespace_use_clause":
                        imports.append(self._use_clause_fqn(child, prefix))
                    elif child.type == "namespace_use_group":
                        for clause in child.children:
                            if clause.type == "namespace_use_clause":
                                imports.append(self._use_clause_fqn(clause, prefix))
                continue
            stack.extend(node.children)
        return sorted(set(imports))

    @staticmethod
    def _use_clause_fqn(clause: Any, prefix: str) -> str:
        """Extract the qualified name of a ``namespace_use_clause`` (drop alias)."""
        for child in clause.children:
            if child.type in ("qualified_name", "name", "namespace_name"):
                return prefix + _text(child)
        return prefix + _text(clause)

    # -- function / call collection -------------------------------------------

    def _collect(
        self, root: Any
    ) -> tuple[
        list[tuple[str, Any, str | None, bool]],
        list[tuple[str | None, str | None, Any]],
    ]:
        """Walk ``root`` collecting function definitions and calls.

        Returns ``(functions, calls)``:
        * ``functions`` -- ``(qualname, node, class_name_or_None, abstract)``. A
          top-level function's qualname is its name; a method's is
          ``ClassName.method``. ``abstract`` is ``True`` for a bodiless method
          declaration (an ``abstract`` method or an interface member): the node
          is still emitted but must never be a call target.
        * ``calls`` -- ``(enclosing_qualname_or_None, enclosing_class_or_None,
          call_node)``. ``enclosing_qualname`` is ``None`` for module-level code
          (attributed to the module node).
        """
        functions: list[tuple[str, Any, str | None, bool]] = []
        calls: list[tuple[str | None, str | None, Any]] = []

        def visit(node: Any, enclosing: str | None, cls: str | None) -> None:
            for child in node.children:
                ctype = child.type
                if ctype == "function_definition":
                    name_node = child.child_by_field_name("name")
                    if name_node is None:
                        continue
                    qual = _text(name_node)
                    functions.append((qual, child, None, False))
                    body = child.child_by_field_name("body")
                    if body is not None:
                        visit(body, qual, None)
                elif ctype == "anonymous_class":
                    # An anonymous class (``new class { ... }``) is NOT the
                    # enclosing named class: its methods must not be attributed
                    # to that class (no ``fn:Outer.helper`` node, and the outer
                    # ``$this->helper()`` must stay unresolved). Visit its body
                    # with ``cls=None`` so its bodiless-skip logic drops the
                    # methods entirely rather than binding them to the outer
                    # class.
                    for sub in child.children:
                        if sub.type == "declaration_list":
                            visit(sub, enclosing, None)
                elif ctype in _CLASSLIKE:
                    name_node = child.child_by_field_name("name")
                    class_name = _text(name_node) if name_node is not None else None
                    body = child.child_by_field_name("body")
                    if body is not None:
                        visit(body, enclosing, class_name)
                elif ctype == "method_declaration":
                    name_node = child.child_by_field_name("name")
                    if name_node is None or cls is None:
                        continue
                    qual = f"{cls}.{_text(name_node)}"
                    body = child.child_by_field_name("body")
                    functions.append((qual, child, cls, body is None))
                    if body is not None:
                        visit(body, qual, cls)
                else:
                    if ctype in (
                        "function_call_expression",
                        "member_call_expression",
                        "scoped_call_expression",
                    ):
                        calls.append((enclosing, cls, child))
                    # Descend; a call's own argument subtree (closures, nested
                    # calls) is attributed to the same enclosing function.
                    visit(child, enclosing, cls)

        visit(root, None, None)
        return functions, calls

    # -- call resolution ------------------------------------------------------

    def _resolve_call(
        self,
        call: Any,
        enclosing_class: str | None,
        local_quals: set[str],
        class_methods: dict[str, set[str]],
    ) -> tuple[str, ...]:
        ctype = call.type

        if ctype == "function_call_expression":
            func = call.child_by_field_name("function")
            if func is not None and func.type == "name":
                name = _text(func)
                if name in local_quals:
                    return ("fn", name)
                return ("unresolved", f"{name}()")
            return ("unresolved", self._call_repr(call))

        if ctype == "member_call_expression":
            obj = call.child_by_field_name("object")
            name_node = call.child_by_field_name("name")
            method = _text(name_node) if name_node is not None else "?"
            # Only ``$this->method()`` is resolvable, and only to a method of the
            # enclosing class defined in this file.
            if (
                obj is not None
                and obj.type == "variable_name"
                and _text(obj) == "$this"
                and enclosing_class is not None
                and method in class_methods.get(enclosing_class, set())
            ):
                return ("fn", f"{enclosing_class}.{method}")
            return ("unresolved", self._call_repr(call))

        if ctype == "scoped_call_expression":
            scope = call.child_by_field_name("scope")
            name_node = call.child_by_field_name("name")
            method = _text(name_node) if name_node is not None else "?"
            if scope is not None and name_node is not None:
                scope_text = _text(scope)
                # self:: / static:: -> enclosing class.
                if (
                    scope.type == "relative_scope"
                    and scope_text in _SELF_SCOPES
                    and enclosing_class is not None
                    and method in class_methods.get(enclosing_class, set())
                ):
                    return ("fn", f"{enclosing_class}.{method}")
                # ClassName:: where ClassName is a class defined in this file.
                if (
                    scope.type == "name"
                    and method in class_methods.get(scope_text, set())
                ):
                    return ("fn", f"{scope_text}.{method}")
            return ("unresolved", self._call_repr(call))

        return ("unresolved", self._call_repr(call))

    @staticmethod
    def _call_repr(call: Any) -> str:
        """A compact, readable representation of an unresolved call target."""
        for field in ("function", "name"):
            part = call.child_by_field_name(field)
            if part is not None:
                obj = call.child_by_field_name("object")
                scope = call.child_by_field_name("scope")
                if obj is not None:
                    return f"{_text(obj)}->{_text(part)}()"
                if scope is not None:
                    return f"{_text(scope)}::{_text(part)}()"
                return f"{_text(part)}()"
        return _text(call).split("(", 1)[0] + "()"

    # -- entry points (routes) ------------------------------------------------

    def _extract_routes(
        self,
        root: Any,
        relpath: str,
        local_quals: set[str],
        imports: list[str],
        graph: Any,
    ) -> None:
        # A Slim route is only honoured when its receiver variable was bound,
        # in this file, to a genuine Slim application (``new \Slim\App(...)`` or
        # ``AppFactory::create()``). This mirrors the receiver-binding care the
        # Python/JS analyzers take, so an unrelated ``$x->get("key")`` (e.g. a
        # cache) is never mistaken for an HTTP entry point.
        slim_app_vars = self._slim_app_vars(root, imports)

        stack = [root]
        while stack:
            node = stack.pop()
            ntype = node.type

            if ntype == "scoped_call_expression":
                self._laravel_route(node, relpath, local_quals, graph)
            elif ntype == "member_call_expression":
                self._slim_route(node, relpath, slim_app_vars, graph)
            elif ntype == "method_declaration":
                self._symfony_route(node, relpath, local_quals, graph)

            stack.extend(node.children)

    def _slim_app_vars(self, root: Any, imports: list[str]) -> set[str]:
        """Variable names bound in-file to a Slim ``App`` instance.

        Recognises ``$app = new \\Slim\\App(...)`` (or a bare ``new App()`` when
        ``Slim\\App`` is imported via ``use``) and ``$app = AppFactory::create()``.
        """
        # Was ``Slim\App`` pulled in with a ``use`` statement? Then a bare
        # ``new App()`` is soundly the Slim app.
        app_imported = any(imp.rsplit("\\", 1)[-1] == "App" and "Slim" in imp.split("\\") for imp in imports)

        app_vars: set[str] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if (
                    left is not None
                    and left.type == "variable_name"
                    and right is not None
                    and self._is_slim_app_ctor(right, app_imported)
                ):
                    app_vars.add(_text(left))
            stack.extend(node.children)
        return app_vars

    @staticmethod
    def _is_slim_app_ctor(expr: Any, app_imported: bool) -> bool:
        """True if ``expr`` constructs a Slim application."""
        if expr.type == "object_creation_expression":
            for child in expr.children:
                if child.type in ("qualified_name", "name"):
                    segments = _text(child).strip("\\").split("\\")
                    if segments[-1:] == ["App"] and ("Slim" in segments or app_imported):
                        return True
                    return False
            return False
        if expr.type == "scoped_call_expression":
            scope = expr.child_by_field_name("scope")
            name_node = expr.child_by_field_name("name")
            if (
                scope is not None
                and name_node is not None
                and _text(scope).rsplit("\\", 1)[-1] == "AppFactory"
                and _text(name_node) == "create"
            ):
                return True
        return False

    def _laravel_route(
        self, node: Any, relpath: str, local_quals: set[str], graph: Any
    ) -> None:
        """``Route::post('/path', [Ctrl::class, 'm'])`` / ``'Ctrl@m'``."""
        scope = node.child_by_field_name("scope")
        name_node = node.child_by_field_name("name")
        if scope is None or name_node is None:
            return
        if scope.type != "name" or _text(scope) != "Route":
            return
        verb = _HTTP_VERBS.get(_text(name_node).lower())
        if verb is None:
            return
        args = self._arg_nodes(node)
        if not args:
            return
        path = self._string_value(args[0])
        if path is None:
            return
        handler = self._laravel_handler(args[1]) if len(args) > 1 else None
        self._emit_route(verb, path, handler, "laravel", relpath, local_quals, graph)

    def _slim_route(
        self, node: Any, relpath: str, slim_app_vars: set[str], graph: Any
    ) -> None:
        """``$app->get('/path', ...)`` -- handler left inline (closure etc.)."""
        obj = node.child_by_field_name("object")
        name_node = node.child_by_field_name("name")
        if obj is None or name_node is None:
            return
        # Conservative: the receiver must be a variable bound in this file to a
        # genuine Slim application, so ``$this->get(...)``, ``$cache->get("key")``
        # and other member calls are never mistaken for routes.
        if obj.type != "variable_name" or _text(obj) not in slim_app_vars:
            return
        verb = _HTTP_VERBS.get(_text(name_node).lower())
        if verb is None:
            return
        args = self._arg_nodes(node)
        if not args:
            return
        path = self._string_value(args[0])
        # A Slim route path is always a URL path beginning with ``/``. Anything
        # else (a config key, a cache key) is not a route -- emit nothing.
        if path is None or not path.startswith("/"):
            return
        # Slim handlers are usually inline closures or class strings; resolving
        # them soundly is out of scope, so no handler edge is emitted. Mark the
        # entry point as having an inline handler when the 2nd arg is a closure.
        inline = len(args) > 1 and self._is_closure(args[1])
        self._emit_route(
            verb, path, None, "slim", relpath, set(), graph, inline=inline
        )

    @staticmethod
    def _is_closure(argument: Any) -> bool:
        """True if an ``argument`` wraps an anonymous function / arrow function."""
        for child in _named_children(argument):
            if child.type in ("anonymous_function", "arrow_function"):
                return True
        return False

    def _symfony_route(
        self, method_node: Any, relpath: str, local_quals: set[str], graph: Any
    ) -> None:
        """``#[Route('/path', methods: ['GET'])]`` on a controller method."""
        attrs = method_node.child_by_field_name("attributes")
        name_node = method_node.child_by_field_name("name")
        if attrs is None or name_node is None:
            return
        qual = self._method_qualname(method_node)
        for attribute in self._iter_attributes(attrs):
            # The attribute name is a positional child (not a field); drop any
            # namespace prefix so ``#[Symfony\\...\\Route]`` matches too.
            attr_name = None
            for child in attribute.children:
                if child.type in ("name", "qualified_name"):
                    attr_name = _text(child).rsplit("\\", 1)[-1]
                    break
            if attr_name != "Route":
                continue
            arg_container = attribute.child_by_field_name("parameters")
            if arg_container is None:
                continue
            args = [c for c in arg_container.children if c.type == "argument"]
            path = None
            methods: list[str] = []
            for arg in args:
                arg_name = arg.child_by_field_name("name")
                if arg_name is not None and _text(arg_name) == "methods":
                    methods = self._string_array(arg)
                elif arg_name is None and path is None:
                    path = self._string_value(arg)
            if path is None:
                continue
            verbs = methods or ["ANY"]
            handler = qual if qual in local_quals else None
            for verb in verbs:
                self._emit_route(
                    verb, path, handler, "symfony", relpath, local_quals, graph
                )

    @staticmethod
    def _method_qualname(method_node: Any) -> str | None:
        name_node = method_node.child_by_field_name("name")
        if name_node is None:
            return None
        # The enclosing class is the declaration_list's parent.
        cur = method_node.parent
        while cur is not None and cur.type not in _CLASSLIKE:
            cur = cur.parent
        if cur is None:
            return None
        class_name_node = cur.child_by_field_name("name")
        if class_name_node is None:
            return None
        return f"{_text(class_name_node)}.{_text(name_node)}"

    def _emit_route(
        self,
        method: str,
        path: str,
        handler: str | None,
        framework: str,
        relpath: str,
        local_quals: set[str],
        graph: Any,
        inline: bool = False,
    ) -> None:
        ep_id = f"ep:{method}:{path}"
        # The handler edge is sound only when the handler is a function/method
        # defined in THIS file. Inline closures / handlers in other files get an
        # entrypoint but no fabricated fn edge.
        resolvable = handler if (handler is not None and handler in local_quals) else None

        existing = graph.get_node(ep_id)
        if existing is not None:
            # Id collision: keep the first entrypoint's handler, never overwrite
            # it. Record any additional resolvable handler for the same route so
            # the clash is visible rather than silently adding a second edge.
            if resolvable is not None and (
                existing.attrs.get("handler") != resolvable
                or existing.attrs.get("handler_file") != relpath
            ):
                collisions = existing.attrs.setdefault("handler_collisions", [])
                entry = {"handler": resolvable, "handler_file": relpath}
                if entry not in collisions:
                    collisions.append(entry)
                graph.add_edge(
                    ep_id, f"fn:{relpath}:{resolvable}", "route_to_handler"
                )
            return

        attrs: dict[str, Any] = {
            "method": method,
            "path": path,
            "framework": framework,
            "handler": resolvable,
            "handler_file": relpath if resolvable is not None else None,
        }
        if inline and resolvable is None:
            attrs["inline_handler"] = True
        graph.add_node(ep_id, "entrypoint", f"{method} {path}", **attrs)
        if resolvable is not None:
            graph.add_edge(ep_id, f"fn:{relpath}:{resolvable}", "route_to_handler")

    # -- argument / literal helpers -------------------------------------------

    @staticmethod
    def _arg_nodes(call: Any) -> list[Any]:
        args = call.child_by_field_name("arguments")
        if args is None:
            return []
        return [c for c in args.children if c.type == "argument"]

    def _string_value(self, argument: Any) -> str | None:
        """Return the string-literal value of an ``argument`` (or raw string)."""
        node = argument
        # Unwrap wrapper nodes (``argument``, array element) to the expression.
        while node.type in ("argument", "array_element_initializer"):
            named = _named_children(node)
            if not named:
                return None
            node = named[0]
        if node.type in ("string", "encapsed_string"):
            # An interpolated double-quoted string (``"/users/$id"``) parses as an
            # ``encapsed_string`` with an interpolation child (e.g. a
            # ``variable_name``) alongside its ``string_content`` fragments.
            # Returning the first fragment would silently truncate the path to
            # ``/users/``; a partial path is a wrong fact, so return ``None``
            # (mirrors the JS analyzer returning ``None`` for template strings).
            if any(c.type != "string_content" for c in node.named_children):
                return None
            for child in node.children:
                if child.type == "string_content":
                    return _text(child)
            # Empty string literal ('' has no string_content child).
            return ""
        return None

    def _string_array(self, argument: Any) -> list[str]:
        """Return the string values of an array-literal argument, upper-cased."""
        named = _named_children(argument)
        values: list[str] = []
        for node in named:
            if node.type == "array_creation_expression":
                for elt in node.children:
                    if elt.type == "array_element_initializer":
                        val = self._string_value(elt)
                        if val is not None:
                            values.append(val.upper())
        return values

    def _laravel_handler(self, argument: Any) -> str | None:
        """Resolve a Laravel handler arg to a ``ClassName.method`` qualname.

        Handles ``[Ctrl::class, 'method']`` and the string form ``'Ctrl@method'``.
        Inline closures (and anything else) return ``None`` -- no edge.
        """
        named = _named_children(argument)
        if not named:
            return None
        node = named[0]
        if node.type == "array_creation_expression":
            elts = [c for c in node.children if c.type == "array_element_initializer"]
            if len(elts) != 2:
                return None
            class_name = self._class_const_name(elts[0])
            method = self._string_value(elts[1])
            if class_name and method:
                return f"{class_name}.{method}"
            return None
        if node.type in ("string", "encapsed_string"):
            raw = self._string_value(argument)
            if raw and "@" in raw:
                cls, _, method = raw.partition("@")
                cls = cls.rsplit("\\", 1)[-1]  # drop any namespace prefix
                if cls and method:
                    return f"{cls}.{method}"
        return None

    @staticmethod
    def _class_const_name(element: Any) -> str | None:
        """Extract ``Ctrl`` from a ``Ctrl::class`` array element."""
        for child in element.children:
            if child.type == "class_constant_access_expression":
                for sub in child.children:
                    if sub.type in ("name", "qualified_name"):
                        return _text(sub).rsplit("\\", 1)[-1]
        return None

    @staticmethod
    def _iter_attributes(attribute_list: Any) -> list[Any]:
        """Yield every ``attribute`` node inside an ``attribute_list``."""
        found: list[Any] = []
        stack = [attribute_list]
        while stack:
            node = stack.pop()
            if node.type == "attribute":
                found.append(node)
            stack.extend(node.children)
        return found
