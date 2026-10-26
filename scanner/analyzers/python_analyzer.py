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

        # Entry points (routes). Decorator + Django detection is unchanged;
        # registry-style registration (Flask-RESTful ``add_resource``,
        # ``add_url_rule``, FastAPI ``add_api_route``) and blueprint/router
        # prefix composition are resolved on top of the same node/edge shape.
        route_objects = self._route_objects(tree)
        ctor_prefix = self._ctor_prefixes(tree)
        mount_prefix = self._mount_prefixes(tree, route_objects)
        self._extract_routes(
            functions, relpath, graph, route_objects, ctor_prefix, mount_prefix
        )
        self._extract_registry_routes(
            tree,
            symtab,
            relpath,
            repo_index,
            graph,
            route_objects,
            ctor_prefix,
            mount_prefix,
            mod_id,
        )
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

    def _emit_entrypoint(
        self,
        graph: Any,
        method: str,
        path: str,
        framework: str,
        relpath: str,
        handler_qual: str | None = None,
        handler_file: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit (or merge into) an ``ep:`` node and its handler edge.

        Shared by decorator and registry-style detection. When ``handler_qual``
        is ``None`` the handler could not be soundly resolved, so no
        ``route_to_handler`` edge is created (a missing edge beats a wrong one);
        ``extra`` may then carry ``unresolved_handler`` for visibility.
        """
        ep_id = f"ep:{method}:{path}"
        existing = graph.get_node(ep_id)
        if existing is not None:
            # Id collision: keep the first handler, never overwrite it. Record
            # any additional handler declaring the same route so the clash is
            # visible rather than silent (``handler_collisions`` convention).
            if handler_qual is not None:
                if (
                    existing.attrs.get("handler") != handler_qual
                    or existing.attrs.get("handler_file") != handler_file
                ):
                    collisions = existing.attrs.setdefault("handler_collisions", [])
                    entry = {"handler": handler_qual, "handler_file": handler_file}
                    if entry not in collisions:
                        collisions.append(entry)
                graph.add_edge(
                    ep_id, f"fn:{handler_file}:{handler_qual}", "route_to_handler"
                )
            return

        attrs: dict[str, Any] = {
            "method": method,
            "path": path,
            "framework": framework,
        }
        if handler_qual is not None:
            attrs["handler"] = handler_qual
            attrs["handler_file"] = handler_file
        if extra:
            attrs.update(extra)
        graph.add_node(ep_id, "entrypoint", f"{method} {path}", **attrs)
        if handler_qual is not None:
            graph.add_edge(
                ep_id, f"fn:{handler_file}:{handler_qual}", "route_to_handler"
            )

    def _extract_routes(
        self,
        functions: list[tuple[str, ast.AST]],
        relpath: str,
        graph: Any,
        route_objects: dict[str, str],
        ctor_prefix: dict[str, tuple[str, str | None]],
        mount_prefix: dict[str, tuple[str, str | None]],
    ) -> None:
        for qual, fnode in functions:
            for decorator in getattr(fnode, "decorator_list", []):
                route = self._route_from_decorator(decorator, route_objects)
                if route is None:
                    continue
                methods, local_path, framework, obj_var = route
                full_path, prefix_unresolved = self._compose_path(
                    framework, obj_var, local_path, ctor_prefix, mount_prefix
                )
                extra = {"prefix_unresolved": True} if prefix_unresolved else None
                for method in methods:
                    self._emit_entrypoint(
                        graph,
                        method,
                        full_path,
                        framework,
                        relpath,
                        handler_qual=qual,
                        handler_file=relpath,
                        extra=extra,
                    )

    def _route_from_decorator(
        self, decorator: ast.AST, route_objects: dict[str, str]
    ) -> tuple[list[str], str, str, str] | None:
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
            return (methods, path, framework, func.value.id)
        if attr_lower in _METHOD_DECORATORS:
            return ([_METHOD_DECORATORS[attr_lower]], path, framework, func.value.id)
        return None

    # -- registry-style route registration (non-decorator) --------------------

    def _extract_registry_routes(
        self,
        tree: ast.AST,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
        graph: Any,
        route_objects: dict[str, str],
        ctor_prefix: dict[str, tuple[str, str | None]],
        mount_prefix: dict[str, tuple[str, str | None]],
        mod_id: str,
    ) -> None:
        """Detect route registration performed by a *call* rather than a decorator.

        * Flask-RESTful ``<api>.add_resource(Cls, "/p", ...)`` (and subclass
          wrappers such as ``add_org_resource``) where ``api`` is an ``Api``
          instance or an instance of a subclass of ``Api``;
        * Flask ``<app|bp>.add_url_rule("/p", view_func=f, methods=[...])``;
        * FastAPI ``<app|router>.add_api_route("/p", handler, methods=[...])``.

        Cardinal rule: only a recognised registrar call on a recognised receiver
        with a STRING-LITERAL path produces an entrypoint, and a verb route is
        only emitted when that verb method is actually defined on the resolved
        Resource class. Everything else is recorded as unresolved, never guessed.
        """
        api_objects = self._api_objects(tree, symtab)
        unresolved: list[str] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            ):
                continue
            recv = func.value.id
            meth = func.attr

            if recv in api_objects and "resource" in meth.lower():
                self._handle_add_resource(
                    node, symtab, relpath, repo_index, graph, unresolved
                )
            elif recv in route_objects and meth == "add_url_rule":
                self._handle_imperative_rule(
                    node,
                    symtab,
                    relpath,
                    repo_index,
                    graph,
                    route_objects[recv],
                    recv,
                    ctor_prefix,
                    mount_prefix,
                    unresolved,
                    path_index=0,
                    handler_index=2,
                    handler_kwarg="view_func",
                )
            elif recv in route_objects and meth == "add_api_route":
                self._handle_imperative_rule(
                    node,
                    symtab,
                    relpath,
                    repo_index,
                    graph,
                    route_objects[recv],
                    recv,
                    ctor_prefix,
                    mount_prefix,
                    unresolved,
                    path_index=0,
                    handler_index=1,
                    handler_kwarg="endpoint",
                )

        if unresolved:
            mod = graph.get_node(mod_id)
            if mod is not None:
                prior = mod.attrs.get("unresolved_routes", [])
                mod.attrs["unresolved_routes"] = prior + unresolved

    def _handle_add_resource(
        self,
        node: ast.Call,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
        graph: Any,
        unresolved: list[str],
    ) -> None:
        if not node.args:
            return
        cls_arg = node.args[0]
        # Every positional string-literal arg after the class is a mount path.
        paths = [
            a.value
            for a in node.args[1:]
            if isinstance(a, ast.Constant) and isinstance(a.value, str)
        ]
        resolved = self._resolve_class_verbs(cls_arg, symtab, relpath, repo_index)
        if resolved is None:
            unresolved.append(
                f"add_resource: cannot resolve Resource class "
                f"{self._safe_unparse(cls_arg)}"
            )
            return
        cls_relpath, cls_name, verbs = resolved
        if not paths:
            unresolved.append(
                f"add_resource({cls_name}): no string-literal path argument"
            )
            return
        for path in paths:
            for method, qual in verbs:
                self._emit_entrypoint(
                    graph,
                    method,
                    path,
                    "flask-restful",
                    relpath,
                    handler_qual=qual,
                    handler_file=cls_relpath,
                )

    def _handle_imperative_rule(
        self,
        node: ast.Call,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
        graph: Any,
        framework: str,
        recv: str,
        ctor_prefix: dict[str, tuple[str, str | None]],
        mount_prefix: dict[str, tuple[str, str | None]],
        unresolved: list[str],
        *,
        path_index: int,
        handler_index: int,
        handler_kwarg: str,
    ) -> None:
        """Handle ``add_url_rule`` / ``add_api_route`` imperative registration."""
        if len(node.args) <= path_index:
            return
        path_arg = node.args[path_index]
        if not (isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str)):
            unresolved.append(
                f"{recv}.{node.func.attr}: non-literal path "  # type: ignore[attr-defined]
                f"{self._safe_unparse(path_arg)}"
            )
            return
        local_path = path_arg.value

        view = self._kwarg_value(node, handler_kwarg)
        if view is None and len(node.args) > handler_index:
            view = node.args[handler_index]

        full_path, prefix_unresolved = self._compose_path(
            framework, recv, local_path, ctor_prefix, mount_prefix
        )
        base_extra: dict[str, Any] = {}
        if prefix_unresolved:
            base_extra["prefix_unresolved"] = True

        # Class-based view: ``view_func=Cls.as_view('name')`` -> enumerate the
        # HTTP-verb methods actually defined on the class.
        if (
            isinstance(view, ast.Call)
            and isinstance(view.func, ast.Attribute)
            and view.func.attr == "as_view"
            and isinstance(view.func.value, ast.Name)
        ):
            resolved = self._resolve_class_verbs(
                view.func.value, symtab, relpath, repo_index
            )
            if resolved is not None:
                cls_relpath, _cls_name, verbs = resolved
                for method, qual in verbs:
                    self._emit_entrypoint(
                        graph,
                        method,
                        full_path,
                        framework,
                        relpath,
                        handler_qual=qual,
                        handler_file=cls_relpath,
                        extra=base_extra or None,
                    )
                return
            unresolved.append(
                f"{recv}.{node.func.attr}: cannot resolve view class "  # type: ignore[attr-defined]
                f"{self._safe_unparse(view)}"
            )

        methods = self._methods_kwarg(node) or ["GET"]
        handler_qual, handler_file = self._resolve_handler_ref(
            view, symtab, relpath, repo_index
        )
        extra = dict(base_extra)
        if handler_qual is None and view is not None:
            extra["unresolved_handler"] = self._safe_unparse(view)
        for method in methods:
            self._emit_entrypoint(
                graph,
                method,
                full_path,
                framework,
                relpath,
                handler_qual=handler_qual,
                handler_file=handler_file,
                extra=extra or None,
            )

    def _resolve_class_verbs(
        self,
        cls_arg: ast.AST,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
    ) -> tuple[str, str, list[tuple[str, str]]] | None:
        """Resolve a class reference to ``(relpath, class_name, [(VERB, qual)])``.

        The HTTP-verb methods are those ``get/post/put/...`` methods actually
        present on the class in the resolved file (per the cross-file index).
        Returns ``None`` when the class or its file cannot be soundly resolved,
        or when it defines no HTTP-verb method -- never inventing a method.
        """
        target_relpath: str | None = None
        cls_name: str | None = None

        if isinstance(cls_arg, ast.Name):
            name = cls_arg.id
            desc = symtab.get(name)
            if desc is None:
                # Not imported: a class defined in this same file (if at all).
                target_relpath, cls_name = relpath, name
            elif desc.get("type") == "external":
                ref = desc.get("ref", "")
                if "." not in ref:
                    return None
                module_part, cls_name = ref.rsplit(".", 1)
                target_relpath = repo_index["modules"].get(module_part)
            else:
                # A function/module/dependency import is not a Resource class.
                return None
        elif isinstance(cls_arg, ast.Attribute) and isinstance(
            cls_arg.value, ast.Name
        ):
            base = symtab.get(cls_arg.value.id)
            if base and base.get("type") == "module" and base.get("relpath"):
                target_relpath, cls_name = base["relpath"], cls_arg.attr
        if not target_relpath or not cls_name:
            return None

        funcs = repo_index["functions"].get(target_relpath, set())
        verbs: list[tuple[str, str]] = []
        for lower, verb in _METHOD_DECORATORS.items():
            qual = f"{cls_name}.{lower}"
            if qual in funcs:
                verbs.append((verb, qual))
        if not verbs:
            return None
        return (target_relpath, cls_name, verbs)

    @staticmethod
    def _resolve_handler_ref(
        view: ast.AST | None,
        symtab: dict[str, dict[str, Any]],
        relpath: str,
        repo_index: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        """Resolve a view/handler expression to ``(qual, relpath)`` or ``(None, None)``."""
        if view is None:
            return (None, None)
        if isinstance(view, ast.Name):
            desc = symtab.get(view.id)
            if desc and desc.get("type") == "func":
                return (desc["qual"], desc["relpath"])
            if view.id in repo_index["functions"].get(relpath, set()):
                return (view.id, relpath)
            return (None, None)
        if isinstance(view, ast.Attribute) and isinstance(view.value, ast.Name):
            desc = symtab.get(view.value.id)
            if desc and desc.get("type") == "module" and desc.get("relpath"):
                funcs = repo_index["functions"].get(desc["relpath"], set())
                if view.attr in funcs:
                    return (view.attr, desc["relpath"])
        return (None, None)

    def _api_objects(
        self, tree: ast.AST, symtab: dict[str, dict[str, Any]]
    ) -> set[str]:
        """Names bound to a Flask-RESTful ``Api`` instance or an ``Api`` subclass.

        Recognises the local name(s) imported from ``flask_restful``/``flask_restx``
        as ``Api`` (honouring ``as`` aliases), every in-file subclass of such a
        name (transitively), and ``flask_restful.Api()`` attribute construction.
        """
        api_bases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in (
                "flask_restful",
                "flask_restx",
            ):
                for alias in node.names:
                    if alias.name == "Api":
                        api_bases.add(alias.asname or "Api")

        classdefs = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]

        def _base_name(base: ast.AST) -> str | None:
            if isinstance(base, ast.Name):
                return base.id
            if isinstance(base, ast.Attribute):
                # ``flask_restful.Api`` written out explicitly as a base.
                if base.attr == "Api" and isinstance(base.value, ast.Name) and (
                    base.value.id in ("flask_restful", "flask_restx")
                ):
                    return "Api"
                return base.attr
            return None

        subclasses: set[str] = set(api_bases)
        changed = True
        while changed:
            changed = False
            for cd in classdefs:
                if cd.name in subclasses:
                    continue
                if any(_base_name(b) in subclasses for b in cd.bases):
                    subclasses.add(cd.name)
                    changed = True

        objects: set[str] = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            ctor = node.value.func
            is_api = False
            if isinstance(ctor, ast.Name) and ctor.id in subclasses:
                is_api = True
            elif isinstance(ctor, ast.Attribute):
                if ctor.attr in subclasses:
                    is_api = True
                elif ctor.attr == "Api" and isinstance(ctor.value, ast.Name) and (
                    ctor.value.id in ("flask_restful", "flask_restx")
                ):
                    is_api = True
            if is_api:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        objects.add(target.id)
        return objects

    # -- prefix composition (blueprint / router) ------------------------------

    def _ctor_prefixes(self, tree: ast.AST) -> dict[str, tuple[str, str | None]]:
        """Map a route-object var to the prefix set at construction.

        ``Blueprint(..., url_prefix="/x")`` and ``APIRouter(prefix="/x")``. The
        value is ``(state, prefix)`` with ``state`` one of ``literal`` /
        ``nonliteral`` (prefix present but not a string literal) / and only vars
        with an explicit prefix kwarg are recorded at all.
        """
        prefixes: dict[str, tuple[str, str | None]] = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            ctor = node.value.func
            cname = (
                ctor.attr
                if isinstance(ctor, ast.Attribute)
                else (ctor.id if isinstance(ctor, ast.Name) else None)
            )
            if cname == "Blueprint":
                kw = "url_prefix"
            elif cname == "APIRouter":
                kw = "prefix"
            else:
                continue
            state, value = self._str_kwarg(node.value, kw)
            if state == "absent":
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = (state, value)
        return prefixes

    def _mount_prefixes(
        self, tree: ast.AST, route_objects: dict[str, str]
    ) -> dict[str, tuple[str, str | None]]:
        """Map a mounted blueprint/router var to the prefix given at mount time.

        ``<app>.register_blueprint(bp, url_prefix="/x")`` (Flask) and
        ``<app>.include_router(router, prefix="/x")`` (FastAPI). Only mounts on a
        recognised route object are honoured, and only when the first positional
        argument is a bare name (the child object).
        """
        mounts: dict[str, tuple[str, str | None]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            ):
                continue
            if func.value.id not in route_objects:
                continue
            if func.attr == "register_blueprint":
                kw = "url_prefix"
            elif func.attr == "include_router":
                kw = "prefix"
            else:
                continue
            if not node.args or not isinstance(node.args[0], ast.Name):
                continue
            state, value = self._str_kwarg(node, kw)
            if state == "absent":
                continue
            mounts[node.args[0].id] = (state, value)
        return mounts

    def _compose_path(
        self,
        framework: str,
        obj_var: str,
        local_path: str,
        ctor_prefix: dict[str, tuple[str, str | None]],
        mount_prefix: dict[str, tuple[str, str | None]],
    ) -> tuple[str, bool]:
        """Compose the full route path, returning ``(path, prefix_unresolved)``.

        Flask *overrides* (``register_blueprint`` url_prefix replaces the
        blueprint's own); FastAPI *concatenates* (include prefix + router prefix
        + route path). When a prefix is present but not a string literal the
        local path is kept and ``prefix_unresolved`` is flagged -- never guessed.
        """
        c_state, c_val = ctor_prefix.get(obj_var, ("absent", None))
        m_state, m_val = mount_prefix.get(obj_var, ("absent", None))

        if framework == "fastapi":
            segments: list[str] = []
            unresolved = False
            for state, val in ((m_state, m_val), (c_state, c_val)):
                if state == "literal":
                    segments.append(val or "")
                elif state == "nonliteral":
                    unresolved = True
            prefix = ""
            for seg in segments:
                prefix = self._join_paths(prefix, seg) if prefix else seg
            full = self._join_paths(prefix, local_path) if prefix else local_path
            return full, unresolved

        # Flask / flask-restful override semantics: the mount prefix, when
        # present, replaces the constructor prefix entirely.
        state, val = (m_state, m_val) if m_state != "absent" else (c_state, c_val)
        if state == "literal":
            return self._join_paths(val, local_path), False
        if state == "nonliteral":
            return local_path, True
        return local_path, False

    @staticmethod
    def _join_paths(prefix: str | None, path: str) -> str:
        if not prefix:
            return path
        left = prefix.rstrip("/")
        if not path or path == "/":
            return left if path != "/" else left + "/"
        right = path if path.startswith("/") else "/" + path
        return left + right

    @staticmethod
    def _str_kwarg(call: ast.Call, name: str) -> tuple[str, str | None]:
        """Classify a kwarg as ``literal`` (+value), ``nonliteral``, or ``absent``."""
        for keyword in call.keywords:
            if keyword.arg == name:
                if isinstance(keyword.value, ast.Constant) and isinstance(
                    keyword.value.value, str
                ):
                    return ("literal", keyword.value.value)
                return ("nonliteral", None)
        return ("absent", None)

    @staticmethod
    def _kwarg_value(call: ast.Call, name: str) -> ast.AST | None:
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
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
