"""Shared graph traversal and node -> dict serializers for the MCP tools.

These helpers are the single source of truth for turning knowledge-graph
nodes/edges into the compact JSON the AI tools return. Keeping them here (rather
than inline in each tool) is what lets ``vscan_describe``,
``vscan_call_graph``, ``vscan_trace_entrypoint`` and friends agree on
exactly how a function, dependency, entrypoint or module is represented, with no
copy-paste.

Nothing in this module performs I/O; it only reads an already-scanned
:class:`~scanner.graph.KnowledgeGraph` plus (optionally) a
:class:`~scanner.reachability.ReachabilityResult`.
"""

from __future__ import annotations

from typing import Any

from scanner.graph import Edge, KnowledgeGraph, Node
from scanner.reachability import ReachabilityResult

# How much free text we are willing to inline before truncating, so a single
# docstring or CVE blob never blows the agent's context budget.
_TEXT_LIMIT = 1200


# -- small helpers ------------------------------------------------------------


def clip(text: Any, limit: int = _TEXT_LIMIT) -> Any:
    """Bound a free-text field so one node cannot flood the response."""
    if not isinstance(text, str):
        return text
    if len(text) <= limit:
        return text
    return text[:limit] + " ...[truncated]"


def truncate(items: list[Any], limit: int | None) -> dict[str, Any]:
    """Return ``{"items", "total", "truncated"}`` for a possibly-capped list."""
    items = list(items)
    total = len(items)
    if limit is None or total <= limit:
        return {"items": items, "total": total, "truncated": False}
    return {"items": items[:limit], "total": total, "truncated": True}


def node_label(node: Node) -> str:
    """A short, human-readable label for a node, for search/listing results."""
    a = node.attrs
    if node.kind == "function":
        return a.get("signature") or node.name
    if node.kind == "dependency":
        version = a.get("version")
        return f"{node.name}=={version}" if version else node.name
    if node.kind == "entrypoint":
        return f"{a.get('method', '')} {a.get('path', '')}".strip()
    if node.kind in ("file", "module", "doc"):
        return a.get("relpath") or node.name
    return node.name


# -- edge traversal -----------------------------------------------------------


def out_edges(graph: KnowledgeGraph, node_id: str, kind: str | None = None) -> list[Edge]:
    return [e for e in graph.edges if e.src == node_id and (kind is None or e.kind == kind)]


def in_edges(graph: KnowledgeGraph, node_id: str, kind: str | None = None) -> list[Edge]:
    return [e for e in graph.edges if e.dst == node_id and (kind is None or e.kind == kind)]


def callers(graph: KnowledgeGraph, fn_id: str) -> list[str]:
    """Ids of functions (or modules) that call ``fn_id``."""
    return sorted({e.src for e in in_edges(graph, fn_id, "calls")})


def callees(graph: KnowledgeGraph, fn_id: str) -> dict[str, Any]:
    """Split the outgoing ``calls`` edges of ``fn_id`` into functions and deps.

    Returns ``{"functions": [id, ...], "dependencies": [{id, symbol}, ...]}``.
    Dependency call edges carry the called ``symbol`` (e.g. ``yaml.safe_load``);
    function-to-function edges do not.
    """
    fns: set[str] = set()
    deps: dict[str, set[str]] = {}
    for e in out_edges(graph, fn_id, "calls"):
        dst = graph.get_node(e.dst)
        if dst is None:
            continue
        if dst.kind == "dependency":
            sym = e.attrs.get("symbol")
            bucket = deps.setdefault(e.dst, set())
            if sym:
                bucket.add(sym)
        elif dst.kind == "function":
            fns.add(e.dst)
    dep_list = [
        {"id": dep_id, "symbols": sorted(syms)} for dep_id, syms in sorted(deps.items())
    ]
    return {"functions": sorted(fns), "dependencies": dep_list}


def called_symbols_of_dep(graph: KnowledgeGraph, dep_id: str) -> list[str]:
    """Distinct symbols the repo calls on a dependency (across all call sites)."""
    syms: set[str] = set()
    for e in in_edges(graph, dep_id, "calls"):
        sym = e.attrs.get("symbol")
        if sym:
            syms.add(sym)
    return sorted(syms)


# -- reachability helpers -----------------------------------------------------


def reachable_dep_ids(reachability: ReachabilityResult) -> set[str]:
    return {dep["id"] for dep in reachability.repo.reachable_deps}


def dep_verdict(reachability: ReachabilityResult, dep_id: str) -> str | None:
    return reachability.repo.verdict_by_dep.get(dep_id)


def entrypoints_reaching_dep(
    reachability: ReachabilityResult, dep_id: str
) -> list[dict[str, Any]]:
    """Which entrypoints reach ``dep_id``, with an example path when known."""
    out: list[dict[str, Any]] = []
    for ep in reachability.entrypoints:
        for rd in ep.reachable_dependencies:
            if rd.id == dep_id:
                out.append(
                    {
                        "entrypoint": ep.id,
                        "label": f"{ep.method} {ep.path}",
                        "symbols": rd.symbols,
                        "example_path": rd.example_path,
                    }
                )
                break
    return out


# -- node serializers ---------------------------------------------------------


def serialize_function(
    graph: KnowledgeGraph, node: Node, *, with_edges: bool = True
) -> dict[str, Any]:
    a = node.attrs
    data: dict[str, Any] = {
        "id": node.id,
        "kind": "function",
        "name": node.name,
        "signature": a.get("signature"),
        "docstring": clip(a.get("docstring")),
        "module": a.get("module"),
        "is_method": a.get("is_method", False),
        "location": {"file": a.get("relpath"), "line": a.get("lineno")},
    }
    if with_edges:
        data["callers"] = callers(graph, node.id)
        data["callees"] = callees(graph, node.id)
    docs = a.get("docs")
    if docs:
        data["docs"] = docs
    return data


def serialize_dependency(
    graph: KnowledgeGraph,
    node: Node,
    *,
    reachability: ReachabilityResult | None = None,
) -> dict[str, Any]:
    a = node.attrs
    data: dict[str, Any] = {
        "id": node.id,
        "kind": "dependency",
        "name": node.name,
        "version": a.get("version"),
        "ecosystem": a.get("ecosystem"),
        "resolved": a.get("resolved", False),
        "source_file": a.get("source_file"),
        "called_symbols": called_symbols_of_dep(graph, node.id),
    }
    if reachability is not None:
        data["reachable"] = node.id in reachable_dep_ids(reachability)
        data["verdict"] = dep_verdict(reachability, node.id)
    return data


def serialize_entrypoint(graph: KnowledgeGraph, node: Node) -> dict[str, Any]:
    a = node.attrs
    data: dict[str, Any] = {
        "id": node.id,
        "kind": "entrypoint",
        "name": node.name,
        "method": a.get("method"),
        "path": a.get("path"),
        "framework": a.get("framework"),
        "handler": a.get("handler"),
        "handler_file": a.get("handler_file"),
    }
    docs = a.get("docs")
    if docs:
        data["docs"] = docs
    return data


def serialize_module_or_file(graph: KnowledgeGraph, node: Node) -> dict[str, Any]:
    a = node.attrs
    data: dict[str, Any] = {
        "id": node.id,
        "kind": node.kind,
        "name": node.name,
        "relpath": a.get("relpath"),
    }
    if node.kind == "file":
        data["language"] = a.get("language")
        data["role"] = a.get("role")
        data["size"] = a.get("size")
    if node.kind == "module":
        data["docstring"] = clip(a.get("docstring"))
    functions = sorted(e.dst for e in out_edges(graph, node.id, "declares"))
    declares = []
    imports = []
    for e in out_edges(graph, node.id):
        if e.kind == "declares":
            dst = graph.get_node(e.dst)
            if dst is not None and dst.kind == "dependency":
                declares.append(e.dst)
        elif e.kind == "imports":
            imports.append(e.dst)
    data["functions"] = [f for f in functions if f.startswith("fn:")]
    if declares:
        data["declares_dependencies"] = sorted(set(declares))
    data["imports"] = sorted(set(imports))
    contains = sorted(e.dst for e in out_edges(graph, node.id, "contains"))
    if contains:
        data["contains"] = contains
    return data


def serialize_node(
    graph: KnowledgeGraph,
    node: Node,
    *,
    reachability: ReachabilityResult | None = None,
) -> dict[str, Any]:
    """Dispatch to the right serializer based on node kind."""
    if node.kind == "function":
        return serialize_function(graph, node)
    if node.kind == "dependency":
        return serialize_dependency(graph, node, reachability=reachability)
    if node.kind == "entrypoint":
        return serialize_entrypoint(graph, node)
    if node.kind in ("module", "file"):
        return serialize_module_or_file(graph, node)
    # doc or anything else: minimal.
    return {
        "id": node.id,
        "kind": node.kind,
        "name": node.name,
        "relpath": node.attrs.get("relpath"),
        "excerpt": clip(node.attrs.get("excerpt")),
    }
