"""Go code analyzer built on tree-sitter (``tree_sitter_language_pack``).

For every ``.go`` file this analyzer emits:

* a ``module`` node (``mod:{relpath}`` -- Go has no dotted import path for a
  *file*, so the repo-relative path is used, mirroring how the Python analyzer
  names its module node) and ``function`` nodes, with ``declares`` edges
  module -> function. A method's qualified name carries its receiver type as
  ``Receiver.Method`` (e.g. ``Server.Handle``, with the pointer stripped from
  ``*Server`` and recorded in the ``pointer_receiver`` attr), matching the
  ``Class.method`` convention used by the Python/PHP/JS analyzers;
* ``imports`` edges module -> dependency, produced by resolving each Go import
  path to a ``dep:Go:{module}`` node via **longest-prefix match** against the Go
  dependency nodes the go.mod manifest adapter already placed in the graph
  (``github.com/gin-gonic/gin/binding`` -> ``github.com/gin-gonic/gin``).
  Standard-library imports are recorded in ``stdlib_imports`` on the module node
  and produce no edge;
* ``calls`` edges from the enclosing function to a sibling function in the SAME
  file, or to a dependency reached through an imported package name
  (``gin.Default()`` -> dep ``github.com/gin-gonic/gin`` with
  ``attrs.symbol = 'gin.Default'``);
* ``entrypoint`` nodes and ``route_to_handler`` edges for web routes. A verb
  call (``r.GET("/x", h)``) is only a route when its receiver ``r`` was bound
  in-file to a recognised router constructor (``gin.Default()``/``gin.New()``,
  ``echo.New()``, ``chi.NewRouter()``, ``mux.NewRouter()``, or
  ``http.NewServeMux()``) whose package resolves through the import map -- so an
  HTTP *client* call (``client.Get("/x")``) or KV/cache call (``kv.Put(...)``)
  is NOT mistaken for a route. ``http.HandleFunc`` counts only when ``http`` is
  the stdlib ``net/http`` import (or the receiver is a ``net/http`` mux).

==========================================================================
RESOLUTION BOUNDARY (what later layers would deepen)
==========================================================================

This is a **single-file** analyzer. ``scan.py`` builds its cross-file
``repo_index`` from Python files only, so it holds nothing for Go; Go->Go calls
into functions declared in *other* files are therefore OUT of scope and are left
unresolved rather than guessed. The one piece of cross-file reasoning done here
is the import-path -> dependency mapping, which is reliable in Go because an
import path names its module unambiguously.

As with the Python analyzer, the CARDINAL RULE is: never emit a call / route /
import edge that cannot be resolved soundly. A wrong edge is worse than a
missing one for the reachability reasoning in later layers, so an unresolvable
call is recorded in the ``unresolved_calls`` attribute of its source function
node and NO edge is emitted.

RESOLVED
  * Imports: an import path whose longest matching prefix is a declared Go
    dependency -> ``imports`` edge to that dep; the import's local package name
    (last path segment, or an explicit alias ``gin "..."``) is tracked so calls
    through it resolve back to the dependency.
  * Calls: ``f(...)`` to a bare function declared in the same file; ``pkg.F(...)``
    where ``pkg`` is a dependency's local import name -> dep edge with the dotted
    ``symbol``.

NOT RESOLVED (recorded, never guessed)
  * Method / field calls on a value of unknown type: ``c.Bind()``, ``r.POST()``
    (no type inference / points-to analysis is performed -- the receiver's type
    is not tracked).
  * Calls through an import whose module is not a declared dependency, and calls
    whose callee is a bare name not declared in this file (it may live in another
    Go file -- out of scope -- or be an unmodelled construct).
  * A local binding that shadows an imported package name suppresses resolution
    through that import (the call is left unresolved rather than mis-attributed).
  * Standard-library calls (``fmt.Println``) and Go built-ins (``make``, ``len``,
    ...) are known-not-a-dependency: no edge, and not counted as unresolved.
"""

from __future__ import annotations

from typing import Any

from tree_sitter_language_pack import get_parser

from . import LanguageAnalyzer, register

# HTTP verb methods used by Gin / Echo / Chi routers, matched case-insensitively
# (Gin uses ``GET``; Chi uses ``Get``). ``HandleFunc`` (net/http) is handled
# separately and labelled ``ANY`` because it carries no verb.
_HTTP_VERBS: frozenset[str] = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"})

# Router constructors, keyed by the import-path prefix of the package that
# declares them, mapped to ``(constructor_names, framework)``. A verb call is
# only treated as a route when its receiver was bound in-file to one of these
# (the constructor's package must resolve through the import ``pkg_map``), which
# is what stops an HTTP *client* (``resty.New().Get(...)``) or a KV store
# (``kv.Put(...)``) from fabricating a public entry point. Prefix matching
# tolerates a ``/vN`` module-version segment (``.../echo/v4``, ``.../chi/v5``).
_ROUTER_CONSTRUCTORS: tuple[tuple[str, frozenset[str], str], ...] = (
    ("github.com/gin-gonic/gin", frozenset({"Default", "New"}), "gin"),
    ("github.com/labstack/echo", frozenset({"New"}), "echo"),
    ("github.com/go-chi/chi", frozenset({"NewRouter"}), "chi"),
    ("github.com/gorilla/mux", frozenset({"NewRouter"}), "mux"),
)

# Go predeclared (built-in) functions -- callable by a bare name with no import.
_GO_BUILTINS: frozenset[str] = frozenset(
    {
        "append", "cap", "clear", "close", "complex", "copy", "delete", "imag",
        "len", "make", "max", "min", "new", "panic", "print", "println", "real",
        "recover",
    }
)


@register
class GoAnalyzer(LanguageAnalyzer):
    """Single-file Go analyzer. See the module docstring for the resolution model."""

    language = "go"

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

        source_bytes = source.encode("utf-8")
        tree = get_parser("go").parse(source_bytes)
        root = tree.root_node

        graph.add_node(
            mod_id,
            "module",
            relpath,
            relpath=relpath,
            language="go",
            parse_error=bool(root.has_error) or None,
        )
        graph.add_edge(file_id, mod_id, "contains")

        # -- imports: build local-name -> target map, emit dep edges ----------
        dep_index = self._go_dep_index(graph)
        pkg_map, stdlib = self._process_imports(root, mod_id, dep_index, graph)
        if stdlib:
            node = graph.get_node(mod_id)
            if node is not None:
                node.attrs["stdlib_imports"] = sorted(stdlib)

        # -- functions + declares edges ---------------------------------------
        functions = self._collect_functions(root)
        local_funcs = {
            qual for qual, fnode, is_method, _ptr in functions if not is_method
        }
        for qual, fnode, is_method, pointer in functions:
            fn_id = f"fn:{relpath}:{qual}"
            graph.add_node(
                fn_id,
                "function",
                qual,
                relpath=relpath,
                module=relpath,
                lineno=fnode.start_point[0] + 1,
                is_method=is_method,
                pointer_receiver=pointer or None,
            )
            graph.add_edge(mod_id, fn_id, "declares")

        # -- call edges -------------------------------------------------------
        unresolved: dict[str, list[str]] = {}
        for qual, fnode, _is_method, _ptr in functions:
            src_id = f"fn:{relpath}:{qual}"
            bound = self._bound_names(fnode)
            body = fnode.child_by_field_name("body")
            if body is None:
                continue
            for call in self._iter_calls(body):
                result = self._resolve_call(
                    call, pkg_map, stdlib, bound, local_funcs, relpath
                )
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

        # -- entry points (routes) --------------------------------------------
        self._extract_routes(
            root, functions, pkg_map, stdlib, local_funcs, relpath, graph
        )

    # -- dependency index ------------------------------------------------------

    @staticmethod
    def _go_dep_index(graph: Any) -> list[tuple[str, str]]:
        """Return ``[(module_path, dep_node_id), ...]`` for Go dependencies.

        Sorted longest-module-first so the first prefix match is the longest one.
        """
        deps: list[tuple[str, str]] = []
        for node in graph.nodes_of_kind("dependency"):
            if node.attrs.get("ecosystem") == "Go":
                deps.append((node.name, node.id))
        deps.sort(key=lambda pair: len(pair[0]), reverse=True)
        return deps

    @staticmethod
    def _match_dep(import_path: str, dep_index: list[tuple[str, str]]) -> str | None:
        """Longest-prefix match of ``import_path`` against the Go dep modules."""
        for module, dep_id in dep_index:  # already longest-first
            if import_path == module or import_path.startswith(module + "/"):
                return dep_id
        return None

    @staticmethod
    def _default_package_name(import_path: str) -> str:
        """Default local identifier for an import path, sans an explicit alias.

        It is the last path segment, with a trailing gopkg.in-style major-version
        suffix stripped: ``gopkg.in/yaml.v2`` is imported as ``yaml``,
        ``github.com/gin-gonic/gin`` as ``gin``. This is a sound default (the
        true package name can still differ, which is why an explicit alias always
        wins); it covers the ubiquitous ``.vN`` case so calls resolve.
        """
        last = import_path.rsplit("/", 1)[-1]
        if "." in last:
            head, tail = last.rsplit(".", 1)
            if head and tail.startswith("v") and tail[1:].isdigit():
                return head
        return last

    @staticmethod
    def _is_stdlib(import_path: str) -> bool:
        """A Go stdlib import has no dot in its first path segment.

        ``net/http``, ``fmt``, ``encoding/json`` are stdlib; ``github.com/...``
        and ``gopkg.in/...`` are not.
        """
        first = import_path.split("/", 1)[0]
        return "." not in first

    # -- imports ---------------------------------------------------------------

    def _process_imports(
        self,
        root: Any,
        mod_id: str,
        dep_index: list[tuple[str, str]],
        graph: Any,
    ) -> tuple[dict[str, tuple[str, str]], set[str]]:
        """Walk import declarations.

        Returns ``(pkg_map, stdlib_paths)`` where ``pkg_map`` maps a local package
        name -> ``(dep_node_id, import_path)`` for imports resolved to a declared
        dependency, and ``stdlib_paths`` is the set of standard-library import
        paths (so calls through them are recognised as not-a-dependency).
        """
        pkg_map: dict[str, tuple[str, str]] = {}
        stdlib: set[str] = set()

        for node in self._iter_type(root, "import_spec"):
            path_node = node.child_by_field_name("path")
            if path_node is None:
                continue
            import_path = self._string_value(path_node)
            if import_path is None:
                continue

            # Local name: an explicit alias wins; a blank (``_``) or dot (``.``)
            # import cannot be resolved back to, so it is tracked for no calls.
            name_node = node.child_by_field_name("name")
            alias: str | None = None
            if name_node is not None:
                if name_node.type == "package_identifier":
                    alias = name_node.text.decode("utf-8")
                else:
                    # ``_`` (blank_identifier) or ``.`` (dot import): no usable
                    # local name. Still classify for the stdlib record / edge.
                    alias = None

            if self._is_stdlib(import_path):
                stdlib.add(import_path)
                continue

            dep_id = self._match_dep(import_path, dep_index)
            if dep_id is not None:
                graph.add_edge(mod_id, dep_id, "imports")
                local = alias or self._default_package_name(import_path)
                if local not in (".", "_"):
                    pkg_map[local] = (dep_id, import_path)
            # Non-stdlib import with no matching declared dependency: not a
            # dependency we know about -> no edge, no call resolution (calls
            # through it stay unresolved). Nothing to record soundly.

        return pkg_map, stdlib

    # -- functions -------------------------------------------------------------

    def _collect_functions(self, root: Any) -> list[tuple[str, Any, bool, bool]]:
        """Return ``[(qualname, node, is_method, pointer_receiver), ...]``.

        Go function and method declarations are top-level only (func *literals*
        are anonymous and never declarations), so a single pass over the source
        file's children suffices. A method's qualname is ``Receiver.Method`` with
        the pointer stripped (``*Server`` -> ``Server.Handle``), matching the
        ``Class.method`` convention of the other analyzers; pointer-ness is kept
        in the returned flag (and later the ``pointer_receiver`` node attr).
        """
        functions: list[tuple[str, Any, bool, bool]] = []
        for child in root.children:
            if child.type == "function_declaration":
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    functions.append(
                        (name_node.text.decode("utf-8"), child, False, False)
                    )
            elif child.type == "method_declaration":
                name_node = child.child_by_field_name("name")
                recv, pointer = self._receiver_type(child)
                if name_node is not None and recv is not None:
                    qual = f"{recv}.{name_node.text.decode('utf-8')}"
                    functions.append((qual, child, True, pointer))
        return functions

    @staticmethod
    def _receiver_type(method: Any) -> tuple[str | None, bool]:
        """Return ``(base_type_name, is_pointer)`` for a method receiver.

        ``*Server`` -> ``("Server", True)``; ``Server`` -> ``("Server", False)``.
        ``(None, False)`` if no receiver type can be read.
        """
        recv = method.child_by_field_name("receiver")
        if recv is None:
            return (None, False)
        for param in recv.children:
            if param.type != "parameter_declaration":
                continue
            type_node = param.child_by_field_name("type")
            if type_node is None:
                continue
            cur = type_node
            pointer = False
            # Unwrap a pointer receiver ``*T``.
            if cur.type == "pointer_type":
                pointer = True
                for c in cur.children:
                    if c.type in ("type_identifier", "generic_type", "qualified_type"):
                        cur = c
                        break
            if cur.type == "type_identifier":
                return (cur.text.decode("utf-8"), pointer)
            if cur.type in ("generic_type", "qualified_type"):
                inner = cur.child_by_field_name("name") or cur.child_by_field_name("type")
                if inner is not None:
                    return (inner.text.decode("utf-8"), pointer)
                return (cur.text.decode("utf-8").split("[", 1)[0], pointer)
        return (None, False)

    # -- call resolution -------------------------------------------------------

    @staticmethod
    def _bound_names(fnode: Any) -> set[str]:
        """Names bound locally in a function (params, receiver, ``:=``, ``var``).

        Used only to SUPPRESS resolution: if a call's root identifier is locally
        bound it shadows any imported package of the same name, so the call is
        left unresolved rather than mis-attributed to that import.
        """
        bound: set[str] = set()

        def collect_param_list(node: Any) -> None:
            # A ``parameter_list`` (params, receiver, or result) holds
            # ``parameter_declaration`` / ``variadic_parameter_declaration``
            # children. Each can declare SEVERAL names (``a, yaml int``), so bind
            # every ``identifier`` child -- the type is a ``type_identifier`` /
            # ``qualified_type`` / ... and so is never mistaken for a name.
            for param in node.children:
                if param.type in (
                    "parameter_declaration",
                    "variadic_parameter_declaration",
                ):
                    for c in param.children:
                        if c.type == "identifier":
                            bound.add(c.text.decode("utf-8"))

        def collect_params_and_result(fn: Any) -> None:
            params = fn.child_by_field_name("parameters")
            if params is not None:
                collect_param_list(params)
            # A named result list (``func h() (yaml int)``) also binds names that
            # shadow imports inside the body.
            result = fn.child_by_field_name("result")
            if result is not None and result.type == "parameter_list":
                collect_param_list(result)

        recv = fnode.child_by_field_name("receiver")
        if recv is not None:
            collect_param_list(recv)
        collect_params_and_result(fnode)

        body = fnode.child_by_field_name("body")
        if body is None:
            return bound

        def walk(node: Any) -> None:
            t = node.type
            if t == "func_literal":
                # A nested func literal introduces its own params/result. Binding
                # them (conservatively, into the same flat set) can only SUPPRESS
                # resolution of a shadowing name -- never fabricate an edge -- so
                # it is sound even though it is not precisely scoped.
                collect_params_and_result(node)
            elif t == "short_var_declaration":
                left = node.children[0] if node.children else None
                if left is not None and left.type == "expression_list":
                    for c in left.children:
                        if c.type == "identifier":
                            bound.add(c.text.decode("utf-8"))
            elif t in ("var_spec", "const_spec"):
                for c in node.children:
                    if c.type == "identifier":
                        bound.add(c.text.decode("utf-8"))
            elif t == "range_clause":
                left = node.children[0] if node.children else None
                if left is not None and left.type == "expression_list":
                    for c in left.children:
                        if c.type == "identifier":
                            bound.add(c.text.decode("utf-8"))
            for c in node.children:
                walk(c)

        walk(body)
        return bound

    def _iter_calls(self, node: Any):
        """Yield every ``call_expression`` within ``node`` (depth-first)."""
        if node.type == "call_expression":
            yield node
        for child in node.children:
            yield from self._iter_calls(child)

    def _resolve_call(
        self,
        call: Any,
        pkg_map: dict[str, tuple[str, str]],
        stdlib: set[str],
        bound: set[str],
        local_funcs: set[str],
        relpath: str,
    ) -> tuple[str, ...]:
        """Resolve one call. See the module docstring for the model."""
        func = call.child_by_field_name("function")
        if func is None:
            return ("unresolved", "<call>")

        if func.type == "identifier":
            name = func.text.decode("utf-8")
            if name in bound:
                return ("unresolved", name)
            if name in local_funcs:
                return ("fn", f"fn:{relpath}:{name}")
            if name in _GO_BUILTINS:
                return ("skip",)
            # A bare name that is neither a sibling function nor a built-in may be
            # declared in another Go file (cross-file is out of scope): unresolved.
            return ("unresolved", name)

        if func.type == "selector_expression":
            operand = func.child_by_field_name("operand")
            field = func.child_by_field_name("field")
            if operand is None or field is None:
                return ("unresolved", self._node_repr(func))
            if operand.type != "identifier":
                # ``a.b.C()``, ``f().G()``, etc. -- receiver type unknown.
                return ("unresolved", self._node_repr(func))
            root_name = operand.text.decode("utf-8")
            method = field.text.decode("utf-8")
            if root_name in bound:
                # Local value shadows any package: unknown type -> unresolved.
                return ("unresolved", f"{root_name}.{method}")
            if root_name in pkg_map:
                dep_id, _import_path = pkg_map[root_name]
                return ("dep", dep_id, f"{root_name}.{method}")
            if root_name in {p.rsplit("/", 1)[-1] for p in stdlib} or any(
                p == root_name or p.endswith("/" + root_name) for p in stdlib
            ):
                # Standard-library package call: known, not a dependency.
                return ("skip",)
            return ("unresolved", f"{root_name}.{method}")

        return ("unresolved", self._node_repr(func))

    # -- entry points ----------------------------------------------------------

    def _extract_routes(
        self,
        root: Any,
        functions: list[tuple[str, Any, bool, bool]],
        pkg_map: dict[str, tuple[str, str]],
        stdlib: set[str],
        local_funcs: set[str],
        relpath: str,
        graph: Any,
    ) -> None:
        # A verb call is a route only when its receiver was bound in-file to a
        # recognised router constructor; map each such name -> framework first.
        routers = self._router_vars(root, pkg_map, stdlib)

        # Route-registration calls are statements, so they live inside function
        # bodies. Iterating per function also gives us that function's locally
        # bound names, needed to tell a package-level handler func from a local
        # variable that merely shadows its name (B6).
        for _qual, fnode, _is_method, _ptr in functions:
            body = fnode.child_by_field_name("body")
            if body is None:
                continue
            bound = self._bound_names(fnode)
            for call in self._iter_calls(body):
                func = call.child_by_field_name("function")
                if func is None or func.type != "selector_expression":
                    continue
                operand = func.child_by_field_name("operand")
                field = func.child_by_field_name("field")
                if operand is None or field is None or operand.type != "identifier":
                    continue
                recv_name = operand.text.decode("utf-8")
                method_name = field.text.decode("utf-8")

                if method_name == "HandleFunc":
                    # net/http: the receiver must be the stdlib ``net/http``
                    # package itself, or a ``*ServeMux`` bound from
                    # ``http.NewServeMux()``. Anything else is not a route.
                    if not (
                        self._is_net_http(recv_name, stdlib)
                        or routers.get(recv_name) == "net/http"
                    ):
                        continue
                    http_method = "ANY"
                    framework = "net/http"
                elif method_name.upper() in _HTTP_VERBS:
                    fw = routers.get(recv_name)
                    if fw is None:
                        # Verb call on a non-router receiver: an HTTP client
                        # (``client.Get``), a KV store (``kv.Put``), a cache
                        # (``cache.Delete``), ... NOT a route. The call pass
                        # already records it in ``unresolved_calls``; emit no
                        # entrypoint and no handler edge.
                        continue
                    http_method = method_name.upper()
                    framework = fw
                else:
                    continue

                args = self._named_args(call)
                if not args:
                    continue
                path = self._string_value(args[0])
                # A route path is a string literal beginning with ``/``.
                if path is None or not path.startswith("/"):
                    continue

                handler_arg = args[-1] if len(args) >= 2 else None
                self._emit_route(
                    http_method,
                    path,
                    framework,
                    handler_arg,
                    bound,
                    local_funcs,
                    relpath,
                    graph,
                )

    def _router_vars(
        self,
        root: Any,
        pkg_map: dict[str, tuple[str, str]],
        stdlib: set[str],
    ) -> dict[str, str]:
        """Map each in-file name bound to a router constructor -> framework.

        Scans ``:=`` / ``=`` / ``var`` bindings file-wide (mirroring how the
        Python analyzer tracks route objects over the whole module). The
        constructor's package must resolve through ``pkg_map`` (a real import),
        or be the stdlib ``net/http`` for ``http.NewServeMux()``.
        """
        routers: dict[str, str] = {}

        def walk(node: Any) -> None:
            t = node.type
            if t in ("short_var_declaration", "assignment_statement"):
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    names = [c for c in left.children if c.type == "identifier"]
                    values = [c for c in right.children if c.is_named]
                    for name, value in zip(names, values):
                        fw = self._router_framework(value, pkg_map, stdlib)
                        if fw is not None:
                            routers[name.text.decode("utf-8")] = fw
            elif t == "var_spec":
                value = node.child_by_field_name("value")
                if value is not None:
                    names = [c for c in node.children if c.type == "identifier"]
                    values = [c for c in value.children if c.is_named]
                    for name, val in zip(names, values):
                        fw = self._router_framework(val, pkg_map, stdlib)
                        if fw is not None:
                            routers[name.text.decode("utf-8")] = fw
            for child in node.children:
                walk(child)

        walk(root)
        return routers

    def _router_framework(
        self,
        value: Any,
        pkg_map: dict[str, tuple[str, str]],
        stdlib: set[str],
    ) -> str | None:
        """Framework label if ``value`` is a recognised router constructor call."""
        if value.type != "call_expression":
            return None
        func = value.child_by_field_name("function")
        if func is None or func.type != "selector_expression":
            return None
        operand = func.child_by_field_name("operand")
        field = func.child_by_field_name("field")
        if operand is None or field is None or operand.type != "identifier":
            return None
        pkg = operand.text.decode("utf-8")
        ctor = field.text.decode("utf-8")

        if ctor == "NewServeMux" and self._is_net_http(pkg, stdlib):
            return "net/http"
        if pkg in pkg_map:
            import_path = pkg_map[pkg][1]
            for base, ctors, framework in _ROUTER_CONSTRUCTORS:
                if (
                    import_path == base or import_path.startswith(base + "/")
                ) and ctor in ctors:
                    return framework
        return None

    @staticmethod
    def _is_net_http(name: str, stdlib: set[str]) -> bool:
        """True when ``name`` refers to the stdlib ``net/http`` import.

        ``net/http``'s default local name is ``http``; an aliased stdlib import
        is not tracked (and so stays unresolved, which is sound -- never a false
        route).
        """
        return name == "http" and "net/http" in stdlib

    def _emit_route(
        self,
        http_method: str,
        path: str,
        framework: str,
        handler_arg: Any,
        bound: set[str],
        local_funcs: set[str],
        relpath: str,
        graph: Any,
    ) -> None:
        ep_id = f"ep:{http_method}:{path}"

        # Resolve the handler to a local function node only when it is a bare
        # named reference to a function declared in THIS file AND that name is
        # not locally bound. A locally-bound name (``handler := wrap(x)``) shadows
        # the same-named function and has an unknown runtime target, so it is
        # recorded as an unresolved handler with NO fabricated ``fn:`` edge (B6).
        # A func literal is inline; a selector / cross-file name is not an edge.
        handler_qual: str | None = None
        inline = False
        unresolved_handler: str | None = None
        if handler_arg is not None:
            if handler_arg.type == "identifier":
                cand = handler_arg.text.decode("utf-8")
                if cand in bound:
                    unresolved_handler = cand
                elif cand in local_funcs:
                    handler_qual = cand
                else:
                    # Bare name not declared in this file: cross-file or unknown.
                    unresolved_handler = cand
            elif handler_arg.type == "func_literal":
                inline = True

        existing = graph.get_node(ep_id)
        if existing is not None:
            if handler_qual is not None and (
                existing.attrs.get("handler") != handler_qual
                or existing.attrs.get("handler_file") != relpath
            ):
                collisions = existing.attrs.setdefault("handler_collisions", [])
                entry = {"handler": handler_qual, "handler_file": relpath}
                if entry not in collisions:
                    collisions.append(entry)
            if handler_qual is not None:
                graph.add_edge(ep_id, f"fn:{relpath}:{handler_qual}", "route_to_handler")
            return

        attrs: dict[str, Any] = {
            "method": http_method,
            "path": path,
            "framework": framework,
        }
        if handler_qual is not None:
            attrs["handler"] = handler_qual
            attrs["handler_file"] = relpath
        if inline:
            attrs["inline_handler"] = True
        if unresolved_handler is not None:
            attrs["unresolved_handler"] = unresolved_handler
        graph.add_node(ep_id, "entrypoint", f"{http_method} {path}", **attrs)
        if handler_qual is not None:
            graph.add_edge(ep_id, f"fn:{relpath}:{handler_qual}", "route_to_handler")

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _named_args(call: Any) -> list[Any]:
        arglist = call.child_by_field_name("arguments")
        if arglist is None:
            return []
        return [c for c in arglist.children if c.is_named]

    @staticmethod
    def _string_value(node: Any) -> str | None:
        """Decode a Go string literal to its value, or ``None`` if not a literal.

        An interpreted string is lexed into several children when it contains an
        escape (``"/a\\nb"`` -> content ``/a``, escape ``\\n``, content ``b``), so
        ALL content/escape fragments are concatenated -- returning only the first
        would truncate the path at the first escape (S11).
        """
        if node.type == "interpreted_string_literal":
            parts: list[str] = []
            for child in node.children:
                if child.type in (
                    "interpreted_string_literal_content",
                    "escape_sequence",
                ):
                    parts.append(child.text.decode("utf-8"))
            if parts:
                return "".join(parts)
            text = node.text.decode("utf-8")
            return text[1:-1] if len(text) >= 2 else ""
        if node.type == "raw_string_literal":
            text = node.text.decode("utf-8")
            return text.strip("`")
        return None

    def _iter_type(self, node: Any, type_name: str):
        """Yield every descendant (and ``node`` itself) of the given type."""
        if node.type == type_name:
            yield node
        for child in node.children:
            yield from self._iter_type(child, type_name)

    @staticmethod
    def _node_repr(node: Any) -> str:
        try:
            return node.text.decode("utf-8")[:80]
        except Exception:  # pragma: no cover - text is bytes on real trees
            return "<expr>"
