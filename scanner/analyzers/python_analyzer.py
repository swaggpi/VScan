"""Deep Python code analyzer built on the standard-library :mod:`ast`.

This is the deepest analyzer in the scanner. For every ``.py`` file it emits:

* a ``module`` node and ``function`` nodes (methods carry a qualified name such
  as ``ClassName.method``), with ``declares`` edges module -> function;
* ``imports`` edges module -> module (intra-repo) and module -> dependency
  (when an imported top-level name maps to a declared dependency), with import
  aliases resolved via a per-module symbol table;
* ``calls`` edges from the enclosing function to another intra-repo function or
  to a dependency (with ``attrs.symbol`` carrying the resolved dotted name,
  e.g. ``yaml.load``), resolved through the symbol table;
* ``entrypoint`` nodes and ``route_to_handler`` edges for web routes.

==========================================================================
WHAT CALL RESOLUTION DOES AND DOES NOT HANDLE  (the boundary for later layers)
==========================================================================

The stdlib ``ast`` gives an exact parse, but name *binding* is resolved with a
deliberately shallow, conservative model. Where a target cannot be determined,
the call is recorded as an ``unresolved`` attribute on the source function node
rather than guessed -- a wrong edge is worse than a missing one for the
reachability reasoning in later layers.

RESOLVED
  * ``import x`` / ``import x as y`` / ``import a.b.c`` -- the bound name maps to
    the module (intra-repo) or to a dependency.
  * ``from m import f`` / ``from m import f as g`` -- ``f`` maps to an intra-repo
    function, submodule, or a dependency symbol; relative imports (``from .``,
    ``from ..pkg``) are resolved against the current module path.
  * Direct calls to imported functions: ``f(...)`` -> intra-repo function node.
  * Attribute calls through an import alias: ``y.load(...)`` where
    ``import yaml as y`` -> dependency ``PyYAML`` with ``symbol=yaml.load``;
    ``mod.func(...)`` -> intra-repo function when ``func`` is defined there.
  * Calls to sibling functions defined in the same module.
  * Simple local aliasing of an import: ``p = y; p.load()`` where ``import yaml
    as y`` (one hop, resolved per-function). Name resolution is scoped: a local
    name (parameter, assignment target, ...) that shadows a module import never
    resolves through that import -- e.g. ``def f(y): y.load()`` is unresolved,
    not a PyYAML edge.
  * A small import-name -> PyPI-package map for well-known mismatches
    (yaml->PyYAML, bs4->beautifulsoup4, cv2->opencv-python, PIL->Pillow,
    sklearn->scikit-learn); otherwise the import name is assumed to equal the
    package name (case-normalised).

NOT RESOLVED (recorded as ``unresolved``, never guessed)
  * Method dispatch on instances: ``self.x()``, ``obj.method()`` -- no type
    inference / points-to analysis is performed.
  * Calls through data structures or return values: ``handlers[key]()``,
    ``factory().run()``.
  * Dynamic dispatch: ``getattr(obj, name)()``, ``globals()[...]()``.
  * Names rebound by control flow, comprehension/closure scoping subtleties, or
    ``*`` imports.
  * Decorators other than recognised route decorators are not turned into call
    edges.

A full inter-procedural points-to analysis (type inference, class/instance
modelling, call-through-data) is the clear future extension that would deepen
this layer; the ``unresolved`` records mark exactly where it would plug in.
"""

from __future__ import annotations

import ast
import builtins
from typing import Any

from . import LanguageAnalyzer, register

# Well-known import-name -> PyPI-distribution-name mismatches.
IMPORT_NAME_TO_PACKAGE: dict[str, str] = {
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
}

# HTTP-method decorator names (FastAPI/Flask/APIRouter style) -> HTTP verb.
_METHOD_DECORATORS: dict[str, str] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "head": "HEAD",
    "options": "OPTIONS",
}

# Django URLconf callables.
_DJANGO_URL_FUNCS: frozenset[str] = frozenset({"path", "re_path", "url"})

# Web-app/router constructors -> framework label. A route decorator is only
# honoured when its receiver was bound to one of these, so that unrelated
# ``@x.get(...)`` / ``@x.route(...)`` calls (e.g. ``@cache.get("key")``) are not
# mistaken for HTTP entry points.
_ROUTE_CONSTRUCTORS: dict[str, str] = {
    "Flask": "flask",
    "Blueprint": "flask",
    "FastAPI": "fastapi",
    "APIRouter": "fastapi",
}

_BUILTINS: frozenset[str] = frozenset(dir(builtins))


# --------------------------------------------------------------------------
# Module-path and function discovery (also used by scan.py to build the index)
# --------------------------------------------------------------------------


def module_path_for(relpath: str) -> str:
    """Map a repo-relative ``.py`` path to a dotted module path.

    ``app.py`` -> ``app``; ``utils/config_loader.py`` -> ``utils.config_loader``;
    ``pkg/__init__.py`` -> ``pkg``.
    """
    path = relpath[:-3] if relpath.endswith(".py") else relpath
    parts = [p for p in path.split("/") if p]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _collect(tree: ast.AST) -> tuple[list[tuple[str, ast.AST]], list[tuple[str | None, ast.Call]]]:
    """Walk ``tree`` collecting function definitions and calls.

    Returns ``(functions, calls)`` where ``functions`` is a list of
    ``(qualname, node)`` and ``calls`` is a list of ``(enclosing_qualname,
    call_node)`` with ``enclosing_qualname`` being ``None`` for module-level
    calls. Decorator expressions are excluded from the call list (routes are
    read from decorators separately).
    """
    functions: list[tuple[str, ast.AST]] = []
    calls: list[tuple[str | None, ast.Call]] = []

    def visit(container: ast.AST, prefix: str, enclosing: str | None) -> None:
        for child in ast.iter_child_nodes(container):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                functions.append((qual, child))
                # Recurse into the body (and arg defaults) but not decorators.
                for stmt in child.body:
                    visit(stmt, qual + ".", qual)
                visit(child.args, qual + ".", qual)
            elif isinstance(child, ast.ClassDef):
                # Recurse into the class body with the class prefix so methods
                # are collected as ``ClassName.method`` (an enclosing method, not
                # the module, owns calls in its body).
                visit(child, prefix + child.name + ".", enclosing)
            else:
                if isinstance(child, ast.Call):
                    calls.append((enclosing, child))
                visit(child, prefix, enclosing)

    visit(tree, "", None)
    return functions, calls


def index_source(relpath: str, source: str) -> tuple[str, set[str]]:
    """Return ``(module_path, {function_qualnames})`` for one source file.

    Used by the orchestrator to build the cross-file index before per-file
    analysis, so calls can resolve into functions defined in other files.
    Returns an empty function set on a syntax error.
    """
    module_path = module_path_for(relpath)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        # ValueError covers null bytes; RecursionError covers deeply nested
        # source (both reachable on 3.11+). A single unparsable file must not
        # abort the whole scan.
        return module_path, set()
    functions, _ = _collect(tree)
    return module_path, {qual for qual, _ in functions}


def build_import_index(deps: list[Any]) -> dict[str, str]:
    """Map importable top-level names -> dependency node ids (PyPI only)."""
    index: dict[str, str] = {}
    for dep in deps:
        if dep.ecosystem != "PyPI":
            continue
        dep_id = dep.node_id()
        names: set[str] = set()
        for import_name, package in IMPORT_NAME_TO_PACKAGE.items():
            if package.lower() == dep.name.lower():
                names.add(import_name)
        names.add(dep.name)
        names.add(dep.name.lower())
        names.add(dep.name.replace("-", "_").lower())
        for name in names:
            index.setdefault(name, dep_id)
    return index


# --------------------------------------------------------------------------
# The analyzer
# --------------------------------------------------------------------------


@register
class PythonAnalyzer(LanguageAnalyzer):
    """Deep Python analyzer. See the module docstring for the resolution model."""

    language = "python"

    def analyze(
        self,
        file_node: Any,
        source: str,
        graph: Any,
        repo_index: dict[str, Any],
    ) -> None:
        relpath = file_node.attrs["relpath"]
        module_path = repo_index["module_by_file"].get(relpath) or module_path_for(relpath)
        mod_id = f"mod:{module_path}"
        file_id = f"file:{relpath}"

        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError) as exc:
            # ValueError covers null bytes; RecursionError covers deeply nested
            # source. Record the error on the module node and keep scanning the
            # rest of the repository rather than aborting.
            graph.add_node(
                mod_id, "module", module_path, relpath=relpath, parse_error=str(exc)
            )
            graph.add_edge(file_id, mod_id, "contains")
            return

        docstring = ast.get_docstring(tree)
        graph.add_node(
            mod_id,
            "module",
            module_path,
            relpath=relpath,
            docstring=(docstring[:200] if docstring else None),
        )
        graph.add_edge(file_id, mod_id, "contains")

        symtab = self._build_symbol_table(
            tree, module_path, relpath, mod_id, graph, repo_index
        )
        functions, calls = _collect(tree)
        local_quals = {qual for qual, _ in functions}

        # Function nodes + declares edges.
        for qual, fnode in functions:
            fn_id = f"fn:{relpath}:{qual}"
            graph.add_node(
                fn_id,
                "function",
                qual,
                relpath=relpath,
                module=module_path,
                lineno=getattr(fnode, "lineno", None),
                is_method="." in qual,
            )
            graph.add_edge(mod_id, fn_id, "declares")

        # Per-function scopes (locally bound names + one-hop local aliases) and
        # the module-level alias map. Resolution is scoped so a local name that
        # shadows a module import never produces a dependency/call edge.
        scopes = {qual: self._function_scope(fnode) for qual, fnode in functions}
        module_aliases = self._module_aliases(tree)

        # Call edges.
        unresolved: dict[str, list[str]] = {}
        for enclosing, call in calls:
            if enclosing is None:
                # Module-level code runs on import: attribute it to the module.
                src_id = mod_id
                bound: frozenset[str] = frozenset()
                local_aliases: dict[str, str] = module_aliases
            else:
                src_id = f"fn:{relpath}:{enclosing}"
                bound, local_aliases = scopes.get(enclosing, (frozenset(), {}))
            result = self._resolve_call(
                call.func,
                symtab,
                bound,
                local_aliases,
                module_aliases,
                relpath,
                repo_index,
                local_quals,
            )
            kind = result[0]
            if kind == "fn":
                graph.add_edge(src_id, result[1], "calls")
            elif kind == "dep":
                graph.add_edge(src_id, result[1], "calls", symbol=result[2])
            elif kind == "builtin":
                continue
            else:  # unresolved
                unresolved.setdefault(src_id, []).append(result[1])

        for src_id, reprs in unresolved.items():
            node = graph.get_node(src_id)
            if node is not None:
                node.attrs["unresolved_calls"] = sorted(set(reprs))[:50]
                node.attrs["unresolved_call_count"] = len(reprs)

        # Entry points (routes).
        route_objects = self._route_objects(tree)
        self._extract_routes(functions, relpath, graph, route_objects)
        self._extract_django_urls(tree, symtab, relpath, repo_index, graph)

    # -- symbol table ---------------------------------------------------------

    def _build_symbol_table(
        self,
        tree: ast.AST,
        module_path: str,
        relpath: str,
        mod_id: str,
        graph: Any,
        repo_index: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Build ``{local_name: descriptor}`` and emit ``imports`` edges."""
        symtab: dict[str, dict[str, Any]] = {}
        # A package (``pkg/__init__.py``) resolves ``from .`` to itself, whereas
        # a regular module resolves ``from .`` to its parent package.
        is_package = relpath.endswith("__init__.py")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    full = alias.name
                    top = full.split(".")[0]
                    kind, target = self._classify_import(full, repo_index)
                    if kind == "module":
                        graph.add_edge(mod_id, f"mod:{full}", "imports")
                    elif kind == "dep":
                        graph.add_edge(mod_id, target, "imports")

                    if alias.asname:
                        symtab[alias.asname] = self._module_descriptor(
                            full, kind, target
                        )
                    else:
                        tkind, ttarget = self._classify_import(top, repo_index)
                        symtab[top] = self._module_descriptor(top, tkind, ttarget)

            elif isinstance(node, ast.ImportFrom):
                resolved = self._resolve_relative(
                    node.module or "", node.level, module_path, is_package
                )
                kind, target = self._classify_import(resolved, repo_index)
                if kind == "module" and resolved:
                    graph.add_edge(mod_id, f"mod:{resolved}", "imports")
                elif kind == "dep":
                    graph.add_edge(mod_id, target, "imports")

                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    symtab[local] = self._from_import_descriptor(
                        resolved, alias.name, kind, target, repo_index, mod_id, graph
                    )

        return symtab

    @staticmethod
    def _module_descriptor(module: str, kind: str, target: str | None) -> dict[str, Any]:
        if kind == "dep":
            return {"type": "dep", "dep_id": target, "base": module}
        if kind == "module":
            return {"type": "module", "module": module, "relpath": target}
        return {"type": "external", "ref": module}

    def _from_import_descriptor(
        self,
        resolved_module: str,
        name: str,
        kind: str,
        target: str | None,
        repo_index: dict[str, Any],
        mod_id: str,
        graph: Any,
    ) -> dict[str, Any]:
        if kind == "dep":
            return {
                "type": "dep_symbol",
                "dep_id": target,
                "symbol": f"{resolved_module}.{name}" if resolved_module else name,
            }
        if kind == "module":
            relpath2 = target
            if relpath2 and name in repo_index["functions"].get(relpath2, set()):
                return {"type": "func", "relpath": relpath2, "qual": name}
            sub = f"{resolved_module}.{name}" if resolved_module else name
            if sub in repo_index["modules"]:
                graph.add_edge(mod_id, f"mod:{sub}", "imports")
                return {
                    "type": "module",
                    "module": sub,
                    "relpath": repo_index["modules"][sub],
                }
            # The imported name is neither a known repo function nor a submodule
            # (e.g. ``from m import Loader`` where ``Loader`` is a class). It is a
            # symbol inside ``m``, not the module ``m`` itself -- treat it as
            # external so attribute calls on it stay unresolved rather than being
            # wrongly bound to a top-level function in ``m``.
            return {"type": "external", "ref": sub}
        base = f"{resolved_module}.{name}" if resolved_module else name
        return {"type": "external", "ref": base}

    @staticmethod
    def _classify_import(
        module_str: str, repo_index: dict[str, Any]
    ) -> tuple[str, str | None]:
        """Classify an imported module as intra-repo module, dependency, or external."""
        if not module_str:
            return ("external", None)
        if module_str in repo_index["modules"]:
            return ("module", repo_index["modules"][module_str])
        top = module_str.split(".")[0]
        import_index = repo_index["import_index"]
        if top in import_index:
            return ("dep", import_index[top])
        if module_str in import_index:
            return ("dep", import_index[module_str])
        return ("external", None)

    @staticmethod
    def _resolve_relative(
        module: str, level: int, current_module: str, is_package: bool = False
    ) -> str:
        """Resolve a relative import to an absolute dotted module path.

        ``current_module`` is the dotted path with ``__init__`` already stripped
        (``pkg/__init__.py`` -> ``pkg``). For a package, ``from .`` (level 1)
        refers to the package itself, so the base keeps one extra segment.
        """
        if not level:
            return module
        parts = current_module.split(".") if current_module else []
        depth = len(parts) - level
        if is_package:
            depth += 1
        base = parts[: max(0, depth)]
        if module:
            base = base + module.split(".")
        return ".".join(base)

    # -- scope analysis (per-function binding + aliasing) ---------------------

    @staticmethod
    def _arg_names(args: ast.arguments) -> set[str]:
        """All parameter names bound by an ``ast.arguments`` node."""
        names: set[str] = set()
        for group in (args.posonlyargs, args.args, args.kwonlyargs):
            for arg in group:
                names.add(arg.arg)
        if args.vararg is not None:
            names.add(args.vararg.arg)
        if args.kwarg is not None:
            names.add(args.kwarg.arg)
        return names

    @classmethod
    def _bind_target(cls, target: ast.AST, bound: set[str]) -> None:
        """Record names bound by an assignment/for/with target."""
        if isinstance(target, ast.Name):
            bound.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                cls._bind_target(elt, bound)
        elif isinstance(target, ast.Starred):
            cls._bind_target(target.value, bound)
        # Attribute/Subscript targets (``obj.x = ...``) bind no bare name.

    @classmethod
    def _scope_visit(
        cls, node: ast.AST, bound: set[str], aliases: dict[str, str]
    ) -> None:
        """Collect names bound (and one-hop ``name = name`` aliases) in a scope.

        Nested function/class definitions start their own scope, so only their
        *name* is recorded here and their body is not descended into. A lambda
        shares call attribution with its enclosing function, so its parameters
        are recorded and its body is walked.
        """
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            return
        if isinstance(node, ast.Lambda):
            bound |= cls._arg_names(node.args)
            cls._scope_visit(node.body, bound, aliases)
            return

        if isinstance(node, ast.Assign):
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Name)
            ):
                aliases[node.targets[0].id] = node.value.id
            for target in node.targets:
                cls._bind_target(target, bound)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            cls._bind_target(node.target, bound)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            cls._bind_target(node.target, bound)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    cls._bind_target(item.optional_vars, bound)
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            bound.add(node.target.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.comprehension):
            cls._bind_target(node.target, bound)

        for child in ast.iter_child_nodes(node):
            cls._scope_visit(child, bound, aliases)

    @classmethod
    def _function_scope(cls, fnode: ast.AST) -> tuple[set[str], dict[str, str]]:
        """Return ``(locally_bound_names, one_hop_alias_map)`` for a function."""
        bound: set[str] = set()
        aliases: dict[str, str] = {}
        args = getattr(fnode, "args", None)
        if isinstance(args, ast.arguments):
            bound |= cls._arg_names(args)
        for stmt in getattr(fnode, "body", []):
            cls._scope_visit(stmt, bound, aliases)
        return bound, aliases

    @classmethod
    def _module_aliases(cls, tree: ast.AST) -> dict[str, str]:
        """Collect module-level ``name = other_name`` aliases only."""
        bound: set[str] = set()  # unused at module level (no shadowing there)
        aliases: dict[str, str] = {}
        for stmt in getattr(tree, "body", []):
            cls._scope_visit(stmt, bound, aliases)
        return aliases

    # -- call resolution ------------------------------------------------------

    def _resolve_call(
        self,
        func: ast.AST,
        symtab: dict[str, dict[str, Any]],
        bound: frozenset[str] | set[str],
        local_aliases: dict[str, str],
        module_aliases: dict[str, str],
        relpath: str,
        repo_index: dict[str, Any],
        local_quals: set[str],
    ) -> tuple[str, ...]:
        """Resolve a call target, scoped to the enclosing function.

        ``bound`` is the set of names bound locally in the enclosing function
        (empty for module-level code). A name that is locally bound shadows any
        module import and is resolved ONLY through a one-hop local alias whose
        right-hand side is itself an unshadowed module import; otherwise the call
        is unresolved. Unshadowed names resolve through the module symbol table
        and module-level aliases as before.
        """
        if isinstance(func, ast.Name):
            root = func.id
            attrs: list[str] = []
        elif isinstance(func, ast.Attribute):
            attrs = []
            cur: ast.AST = func
            while isinstance(cur, ast.Attribute):
                attrs.append(cur.attr)
                cur = cur.value
            attrs.reverse()
            if not isinstance(cur, ast.Name):
                return ("unresolved", self._safe_unparse(func))
            root = cur.id
        else:
            return ("unresolved", self._safe_unparse(func))

        unresolved_repr = root if not attrs else f"{root}." + ".".join(attrs)

        if root in bound:
            # Locally shadowed. Accept only a one-hop local alias to an
            # unshadowed module import; never fall back to the module import of
            # the shadowed name itself.
            rhs = local_aliases.get(root)
            if rhs is not None and rhs not in bound and rhs in symtab:
                return self._from_descriptor(
                    symtab[rhs], attrs, relpath, repo_index
                )
            return ("unresolved", unresolved_repr)

        name = self._follow_alias(root, module_aliases)
        if name in symtab:
            return self._from_descriptor(symtab[name], attrs, relpath, repo_index)
        if attrs:
            return ("unresolved", unresolved_repr)
        if name in local_quals:
            return ("fn", f"fn:{relpath}:{name}")
        if name in _BUILTINS:
            return ("builtin",)
        return ("unresolved", name)

    @staticmethod
    def _follow_alias(name: str, alias_map: dict[str, str]) -> str:
        seen: set[str] = set()
        while name in alias_map and name not in seen:
            seen.add(name)
            name = alias_map[name]
        return name

    @staticmethod
    def _from_descriptor(
        desc: dict[str, Any],
        attr_path: list[str],
        relpath: str,
        repo_index: dict[str, Any],
    ) -> tuple[str, ...]:
        dtype = desc["type"]
        suffix = ("." + ".".join(attr_path)) if attr_path else ""

        if dtype == "dep":
            return ("dep", desc["dep_id"], desc["base"] + suffix)
        if dtype == "dep_symbol":
            return ("dep", desc["dep_id"], desc["symbol"] + suffix)
        if dtype == "func":
            if not attr_path:
                return ("fn", f"fn:{desc['relpath']}:{desc['qual']}")
            return ("unresolved", desc["qual"] + suffix)
        if dtype == "module":
            relpath2 = desc.get("relpath")
            if relpath2 and attr_path:
                funcs = repo_index["functions"].get(relpath2, set())
                # Only an exact fully-qualified match is an intra-repo call edge.
                # ``m.func.anything()`` must NOT be guessed to reach ``func``.
                joined = ".".join(attr_path)
                if joined in funcs:
                    return ("fn", f"fn:{relpath2}:{joined}")
            return ("unresolved", f"{desc.get('module', '?')}{suffix}")
        return ("unresolved", f"{desc.get('ref', '?')}{suffix}")

    @staticmethod
    def _safe_unparse(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:  # pragma: no cover - unparse is robust on real trees
            return "<expr>"

    # -- entry points ---------------------------------------------------------

    @classmethod
    def _route_objects(cls, tree: ast.AST) -> dict[str, str]:
        """Map variable names bound to a web-app/router constructor -> framework.

        ``app = Flask(__name__)`` / ``router = APIRouter()`` register ``app`` and
        ``router`` so that only their decorators are treated as routes.
        """
        objects: dict[str, str] = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            ctor = node.value.func
            if isinstance(ctor, ast.Attribute):
                cname = ctor.attr
            elif isinstance(ctor, ast.Name):
                cname = ctor.id
            else:
                continue
            framework = _ROUTE_CONSTRUCTORS.get(cname)
            if framework is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    objects[target.id] = framework
        return objects

    def _extract_routes(
        self,
        functions: list[tuple[str, ast.AST]],
        relpath: str,
        graph: Any,
        route_objects: dict[str, str],
    ) -> None:
        for qual, fnode in functions:
            for decorator in getattr(fnode, "decorator_list", []):
                route = self._route_from_decorator(decorator, route_objects)
                if route is None:
                    continue
                methods, path, framework = route
                for method in methods:
                    ep_id = f"ep:{method}:{path}"
                    existing = graph.get_node(ep_id)
                    if existing is not None:
                        # Id collision: keep the first handler, never overwrite
                        # it. Record any additional handler declaring the same
                        # route so the clash is visible rather than silent.
                        if (
                            existing.attrs.get("handler") != qual
                            or existing.attrs.get("handler_file") != relpath
                        ):
                            collisions = existing.attrs.setdefault(
                                "handler_collisions", []
                            )
                            entry = {"handler": qual, "handler_file": relpath}
                            if entry not in collisions:
                                collisions.append(entry)
                        graph.add_edge(
                            ep_id, f"fn:{relpath}:{qual}", "route_to_handler"
                        )
                        continue
                    graph.add_node(
                        ep_id,
                        "entrypoint",
                        f"{method} {path}",
                        method=method,
                        path=path,
                        handler=qual,
                        handler_file=relpath,
                        framework=framework,
                    )
                    graph.add_edge(ep_id, f"fn:{relpath}:{qual}", "route_to_handler")

    def _route_from_decorator(
        self, decorator: ast.AST, route_objects: dict[str, str]
    ) -> tuple[list[str], str, str] | None:
        if not isinstance(decorator, ast.Call):
            return None
        func = decorator.func
        # Require ``@<name>.<method>(...)`` where <name> is a known route object.
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            return None
        framework = route_objects.get(func.value.id)
        if framework is None:
            return None

        attr_lower = func.attr.lower()
        path = self._first_str_arg(decorator)
        if path is None:
            return None

        if attr_lower == "route":
            methods = self._methods_kwarg(decorator) or ["GET"]
            return (methods, path, framework)
        if attr_lower in _METHOD_DECORATORS:
            return ([_METHOD_DECORATORS[attr_lower]], path, framework)
        return None

    @staticmethod
    def _first_str_arg(call: ast.Call) -> str | None:
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        return None

    @staticmethod
    def _methods_kwarg(call: ast.Call) -> list[str] | None:
        for keyword in call.keywords:
            if keyword.arg == "methods" and isinstance(
                keyword.value, (ast.List, ast.Tuple)
            ):
                methods = [
                    elt.value.upper()
                    for elt in keyword.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
                return methods or None
        return None

    def _extract_django_urls(
        self,
        tree: ast.AST,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
        graph: Any,
    ) -> None:
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id == "urlpatterns"
                    for t in node.targets
                )
                and isinstance(node.value, (ast.List, ast.Tuple))
            ):
                continue
            for elt in node.value.elts:
                if not isinstance(elt, ast.Call):
                    continue
                fn = elt.func
                fname = fn.attr if isinstance(fn, ast.Attribute) else (
                    fn.id if isinstance(fn, ast.Name) else None
                )
                if fname not in _DJANGO_URL_FUNCS:
                    continue
                path = self._first_str_arg(elt)
                if path is None or len(elt.args) < 2:
                    continue
                norm_path = path if path.startswith("/") else "/" + path
                ep_id = f"ep:ANY:{norm_path}"
                graph.add_node(
                    ep_id,
                    "entrypoint",
                    f"ANY {norm_path}",
                    method="ANY",
                    path=norm_path,
                    framework="django",
                )
                view = elt.args[1]
                handler = self._resolve_view(view, symtab, repo_index)
                if handler is not None:
                    graph.add_edge(ep_id, handler, "route_to_handler")

    @staticmethod
    def _resolve_view(
        view: ast.AST,
        symtab: dict[str, dict[str, Any]],
        repo_index: dict[str, Any],
    ) -> str | None:
        if isinstance(view, ast.Name) and view.id in symtab:
            desc = symtab[view.id]
            if desc["type"] == "func":
                return f"fn:{desc['relpath']}:{desc['qual']}"
        if isinstance(view, ast.Attribute) and isinstance(view.value, ast.Name):
            desc = symtab.get(view.value.id)
            if desc and desc.get("type") == "module" and desc.get("relpath"):
                funcs = repo_index["functions"].get(desc["relpath"], set())
                if view.attr in funcs:
                    return f"fn:{desc['relpath']}:{view.attr}"
        return None
