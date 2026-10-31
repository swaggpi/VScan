#!/usr/bin/env python3
"""MCP server exposing the ``vulnreach`` scanner as AI tools.

This server wraps the ``vulnreach`` library *in process* (no HTTP, no shelling
to the CLI) and speaks MCP over **stdio**. It gives an LLM agent three
capabilities over a local source repository:

1. **Navigate** the repo through its knowledge graph instead of reading files
   (``vulnreach_scan_overview``, ``vulnreach_find``, ``vulnreach_describe``,
   ``vulnreach_call_graph``, ``vulnreach_trace_entrypoint``,
   ``vulnreach_dep_reachers``).
2. **Discuss problems** -- reachability-aware vulnerability findings
   (``vulnreach_audit``, ``vulnreach_finding_detail``).
3. **Fix** -- compute remediations and surgically rewrite a manifest pin
   (``vulnreach_remediation``, ``vulnreach_apply_upgrade``).

Every tool returns a compact JSON string so the agent reasons over structured
facts rather than raw file contents. Tools never raise: errors come back as a
``"Error: ..."`` string with actionable guidance.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from mcp.server.fastmcp import FastMCP

from scanner.agent import investigate_usage, triage_findings
from scanner.correlate import report

from . import serialize, state, upgrade
from .state import ToolError

mcp = FastMCP("vulnreach_mcp")

# How many list rows a navigation tool inlines before reporting just a total.
_DEFAULT_LIMIT = 30
_EP_LIMIT = 50

_READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
_READ_ONLY_NETWORK = {**_READ_ONLY, "openWorldHint": True}


# -- shared output / error plumbing ------------------------------------------


def _json(obj: Any) -> str:
    """Serialize a tool result compactly (token-efficient JSON)."""
    return json.dumps(obj, default=str, separators=(",", ":"), ensure_ascii=False)


def _safe(impl: Callable[[], Any]) -> str:
    """Run a tool body, turning any failure into an actionable error string."""
    try:
        return _json(impl())
    except ToolError as exc:
        return f"Error: {exc}"
    except Exception as exc:  # never let a traceback escape a tool
        return f"Error: unexpected {type(exc).__name__}: {exc}"


def _require_node(graph: Any, node_id: str, *, kind: str | None = None) -> Any:
    node = graph.get_node(node_id)
    if node is None:
        raise ToolError(
            f"node not found: {node_id!r}. Use vulnreach_find to look up the "
            "correct id (ids look like 'fn:app.py:submit', 'dep:PyPI:PyYAML', "
            "'ep:POST:/submit')."
        )
    if kind is not None and node.kind != kind:
        raise ToolError(
            f"node {node_id!r} is a {node.kind}, but this tool expects a {kind}."
        )
    return node


# -- input models -------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScanOverviewInput(_Base):
    repo_path: str = Field(
        ..., description="Path to the local repository root (e.g. '.', 'samples/golden-app').",
        min_length=1,
    )
    refresh: bool = Field(
        default=False, description="Re-scan from disk, ignoring the cached graph."
    )


class FindInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    query: str = Field(
        ..., description="Case-insensitive substring to match against node name/id/path "
        "(e.g. 'submit', 'yaml', '/api').",
        min_length=1,
    )
    kind: Optional[Literal["entrypoint", "dependency", "function", "module", "file", "doc"]] = Field(
        default=None, description="Optional node-kind filter."
    )
    limit: int = Field(default=_DEFAULT_LIMIT, description="Max rows to return.", ge=1, le=200)


class DescribeInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    node_id: str = Field(
        ..., description="A graph node id (e.g. 'fn:app.py:submit', 'dep:PyPI:PyYAML', "
        "'ep:POST:/submit', 'mod:app', 'file:app.py').",
        min_length=1,
    )


class CallGraphInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    node_id: str = Field(
        ..., description="A function node id (e.g. 'fn:services.py:ingest').", min_length=1
    )
    direction: Literal["in", "out"] = Field(
        ..., description="'in' = who calls this function; 'out' = what this function calls."
    )
    depth: int = Field(default=1, description="How many call hops to expand (capped at 5).", ge=1, le=5)


class TraceEntrypointInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    entrypoint_id: str = Field(
        ..., description="An entrypoint node id (e.g. 'ep:POST:/submit').", min_length=1
    )


class DepReachersInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    dep_id: str = Field(
        ..., description="A dependency node id (e.g. 'dep:PyPI:PyYAML').", min_length=1
    )


class AuditInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    offline: bool = Field(
        default=False,
        description="Skip all network lookups (OSV/KEV/EPSS) and the model; use only "
        "offline heuristics. Returns no findings offline.",
    )
    explain: bool = Field(
        default=True,
        description="Include advisory triage (exploitability) and usage evidence per finding.",
    )
    refresh: bool = Field(default=False, description="Re-scan and re-correlate, busting caches.")


class FindingDetailInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    dep_id: str = Field(
        ..., description="A dependency node id to deep-dive (e.g. 'dep:PyPI:PyYAML').",
        min_length=1,
    )
    offline: bool = Field(default=False, description="Skip network lookups and the model.")


class RemediationInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    dep_id: Optional[str] = Field(
        default=None, description="A single dependency id; omit for ALL vulnerable deps."
    )
    offline: bool = Field(default=False, description="Skip network lookups and the model.")


class ApplyUpgradeInput(_Base):
    repo_path: str = Field(..., description="Path to the local repository root.", min_length=1)
    dep_id: str = Field(
        ..., description="The dependency to re-pin (e.g. 'dep:PyPI:PyYAML').", min_length=1
    )
    version: str = Field(
        ..., description="The exact version to pin to (e.g. '5.4.1').", min_length=1
    )
    dry_run: bool = Field(
        default=True,
        description="True (default) previews the unified diff only; False writes the file.",
    )


# -- Capability 1: NAVIGATE ---------------------------------------------------


@mcp.tool(name="vulnreach_scan_overview", annotations={"title": "Scan overview", **_READ_ONLY})
def vulnreach_scan_overview(params: ScanOverviewInput) -> str:
    """Scan a repository and return a structural map -- the "understand this repo" entry point.

    Replaces blindly opening files: one call gives you the shape of the codebase
    (counts, languages, entry points) so you can decide where to look next with
    vulnreach_find / vulnreach_describe.

    Args:
        params.repo_path (str): Local repo root.
        params.refresh (bool): Re-scan from disk (default False; the graph is cached).

    Returns (JSON):
        {
          "repo": str,                       # absolute path scanned
          "node_counts": {kind: int},        # entrypoint/dependency/function/module/file/doc
          "edge_counts": {kind: int},
          "languages": [str],
          "entrypoints": int,
          "dependencies": {"total":int,"pinned":int,"unpinned":int,"lockfile_resolved":int},
          "functions": int,
          "top_modules": [{"id","functions"}],   # by function count
          "top_files": [{"file","functions"}],
          "entrypoint_list": {"items":[{"endpoint","handler","id"}],"total":int,"truncated":bool}
        }

    Use when: starting on an unfamiliar repo, or to get entrypoint/dependency counts.
    Don't use when: you already have a node id (use vulnreach_describe).
    """
    def impl() -> dict[str, Any]:
        key, graph = state.get_graph(params.repo_path, refresh=params.refresh)
        summary = graph.summary()
        deps = graph.nodes_of_kind("dependency")
        pinned = sum(1 for d in deps if d.attrs.get("version"))
        lockfile_resolved = sum(1 for d in deps if d.attrs.get("resolved"))
        files = graph.nodes_of_kind("file")
        languages = sorted({f.attrs.get("language") for f in files if f.attrs.get("language")})

        mod_counts = []
        for m in graph.nodes_of_kind("module"):
            fns = [e.dst for e in serialize.out_edges(graph, m.id, "declares") if e.dst.startswith("fn:")]
            if fns:
                mod_counts.append({"id": m.id, "functions": len(fns)})
        mod_counts.sort(key=lambda d: (-d["functions"], d["id"]))

        file_counts: dict[str, int] = {}
        for fn in graph.nodes_of_kind("function"):
            rel = fn.attrs.get("relpath")
            if rel:
                file_counts[rel] = file_counts.get(rel, 0) + 1
        top_files = sorted(
            ({"file": f, "functions": c} for f, c in file_counts.items()),
            key=lambda d: (-d["functions"], d["file"]),
        )

        ep_rows = [
            {
                "endpoint": f"{e.attrs.get('method', '')} {e.attrs.get('path', '')}".strip(),
                "handler": e.attrs.get("handler"),
                "id": e.id,
            }
            for e in graph.nodes_of_kind("entrypoint")
        ]
        ep_rows.sort(key=lambda r: r["endpoint"])

        return {
            "repo": key,
            "node_counts": summary["node_counts"],
            "edge_counts": summary["edge_counts"],
            "languages": languages,
            "entrypoints": len(graph.nodes_of_kind("entrypoint")),
            "dependencies": {
                "total": len(deps),
                "pinned": pinned,
                "unpinned": len(deps) - pinned,
                "lockfile_resolved": lockfile_resolved,
            },
            "functions": len(graph.nodes_of_kind("function")),
            "top_modules": mod_counts[:10],
            "top_files": top_files[:10],
            "entrypoint_list": serialize.truncate(ep_rows, _EP_LIMIT),
        }

    return _safe(impl)


@mcp.tool(name="vulnreach_find", annotations={"title": "Find nodes", **_READ_ONLY})
def vulnreach_find(params: FindInput) -> str:
    """Substring-search the knowledge graph for nodes by name, id or path.

    The fast way to turn a human name ("submit", "yaml", "/api/items") into the
    graph node id that the other tools need.

    Args:
        params.repo_path (str): Local repo root.
        params.query (str): Case-insensitive substring.
        params.kind (str | None): Optional node-kind filter.
        params.limit (int): Max rows (default 30).

    Returns (JSON):
        {"query": str, "matches": {"items":[{"id","kind","label"}],"total":int,"truncated":bool}}

    Use when: you know a name but not the node id.
    Don't use when: you already have an id (use vulnreach_describe).
    """
    def impl() -> dict[str, Any]:
        _, graph = state.get_graph(params.repo_path)
        q = params.query.lower()
        matches = []
        for n in graph.nodes:
            if params.kind and n.kind != params.kind:
                continue
            hay = " ".join(
                filter(None, [n.id, n.name, n.attrs.get("relpath"), n.attrs.get("path")])
            ).lower()
            if q in hay:
                matches.append({"id": n.id, "kind": n.kind, "label": serialize.node_label(n)})
        matches.sort(key=lambda m: (m["kind"], m["id"]))
        return {"query": params.query, "matches": serialize.truncate(matches, params.limit)}

    return _safe(impl)


@mcp.tool(name="vulnreach_describe", annotations={"title": "Describe node", **_READ_ONLY})
def vulnreach_describe(params: DescribeInput) -> str:
    """Full datasheet for one node -- replaces opening the file.

    Args:
        params.repo_path (str): Local repo root.
        params.node_id (str): Any graph node id.

    Returns (JSON), shape depends on node kind:
        function   -> {id,kind,name,signature,docstring,module,location:{file,line},
                       callers:[id],callees:{functions:[id],dependencies:[{id,symbols}]},docs?}
        dependency -> {id,kind,name,version,ecosystem,resolved,source_file,
                       called_symbols:[str],reachable:bool,verdict:str}
        entrypoint -> {id,kind,name,method,path,framework,handler,handler_file,
                       reaches:{reachable_function_count,reachable_dependencies:[id],fully_resolved}}
        module/file-> {id,kind,name,relpath,functions:[id],imports:[id],...}

    Use when: you have a node id and need its details, callers/callees, or reachability.
    Don't use when: you don't know the id yet (use vulnreach_find).
    """
    def impl() -> dict[str, Any]:
        graph, reach = state.get_reachability(params.repo_path)
        node = _require_node(graph, params.node_id)
        data = serialize.serialize_node(graph, node, reachability=reach)
        if node.kind == "entrypoint":
            for ep in reach.entrypoints:
                if ep.id == node.id:
                    data["reaches"] = {
                        "reachable_function_count": ep.reachable_function_count,
                        "reachable_dependencies": [rd.id for rd in ep.reachable_dependencies],
                        "fully_resolved": ep.fully_resolved,
                    }
                    break
        return data

    return _safe(impl)


@mcp.tool(name="vulnreach_call_graph", annotations={"title": "Call graph", **_READ_ONLY})
def vulnreach_call_graph(params: CallGraphInput) -> str:
    """Expand the call graph around a function, inward (callers) or outward (callees).

    Args:
        params.repo_path (str): Local repo root.
        params.node_id (str): A function node id.
        params.direction (str): 'in' (callers) or 'out' (callees).
        params.depth (int): Hops to expand, 1-5 (capped at 5).

    Returns (JSON):
        {"root": id, "direction": str, "depth": int,
         "nodes": [{"id","kind","label"}],
         "edges": [{"src","dst","symbol"}]}

    Use when: tracing how execution flows to/from a function across hops.
    Don't use when: you only need the immediate callers/callees (vulnreach_describe gives those).
    """
    def impl() -> dict[str, Any]:
        _, graph = state.get_graph(params.repo_path)
        root = _require_node(graph, params.node_id, kind="function")
        depth = min(params.depth, 5)
        visited = {root.id}
        frontier = [root.id]
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for _ in range(depth):
            nxt: list[str] = []
            for nid in frontier:
                es = (
                    serialize.out_edges(graph, nid, "calls")
                    if params.direction == "out"
                    else serialize.in_edges(graph, nid, "calls")
                )
                for e in es:
                    sig = (e.src, e.dst, str(e.attrs.get("symbol", "")))
                    if sig not in seen_edges:
                        seen_edges.add(sig)
                        edges.append({"src": e.src, "dst": e.dst, "symbol": e.attrs.get("symbol")})
                    other = e.dst if params.direction == "out" else e.src
                    if other not in visited:
                        visited.add(other)
                        nxt.append(other)
            frontier = nxt
            if not frontier:
                break
        nodes = []
        for nid in sorted(visited):
            n = graph.get_node(nid)
            if n is not None:
                nodes.append({"id": n.id, "kind": n.kind, "label": serialize.node_label(n)})
        return {
            "root": root.id,
            "direction": params.direction,
            "depth": depth,
            "nodes": nodes,
            "edges": edges,
        }

    return _safe(impl)


@mcp.tool(name="vulnreach_trace_entrypoint", annotations={"title": "Trace entrypoint", **_READ_ONLY})
def vulnreach_trace_entrypoint(params: TraceEntrypointInput) -> str:
    """Forward reachability: the functions and dependencies a route can reach.

    Args:
        params.repo_path (str): Local repo root.
        params.entrypoint_id (str): An entrypoint node id (e.g. 'ep:POST:/submit').

    Returns (JSON):
        {"entrypoint","method","path","handlers":[id],"reachable_function_count":int,
         "fully_resolved":bool,
         "reachable_dependencies":[{"id","name","symbols":[str],"verdict","example_path":[id]}]}

    Use when: assessing what one public route exposes.
    Don't use when: you want to know who reaches a dependency (use vulnreach_dep_reachers).
    """
    def impl() -> dict[str, Any]:
        graph, reach = state.get_reachability(params.repo_path)
        _require_node(graph, params.entrypoint_id, kind="entrypoint")
        for ep in reach.entrypoints:
            if ep.id == params.entrypoint_id:
                return {
                    "entrypoint": ep.id,
                    "method": ep.method,
                    "path": ep.path,
                    "handlers": ep.handlers,
                    "reachable_function_count": ep.reachable_function_count,
                    "fully_resolved": ep.fully_resolved,
                    "reachable_dependencies": [
                        {
                            "id": rd.id,
                            "name": rd.name,
                            "symbols": rd.symbols,
                            "verdict": rd.verdict,
                            "example_path": rd.example_path,
                        }
                        for rd in ep.reachable_dependencies
                    ],
                }
        raise ToolError(
            f"entrypoint {params.entrypoint_id!r} has no reachability record "
            "(it may have no resolved handler)."
        )

    return _safe(impl)


@mcp.tool(name="vulnreach_dep_reachers", annotations={"title": "Dependency reachers", **_READ_ONLY})
def vulnreach_dep_reachers(params: DepReachersInput) -> str:
    """Reverse reachability: which entrypoints can reach a dependency ("who can hit this").

    Args:
        params.repo_path (str): Local repo root.
        params.dep_id (str): A dependency node id (e.g. 'dep:PyPI:PyYAML').

    Returns (JSON):
        {"dependency","name","version","verdict","reachable":bool,
         "entrypoints":[{"entrypoint","label","symbols":[str],"example_path":[id]}]}

    Use when: judging whether a vulnerable dependency is actually exposed.
    Don't use when: you want a route's outgoing reach (use vulnreach_trace_entrypoint).
    """
    def impl() -> dict[str, Any]:
        graph, reach = state.get_reachability(params.repo_path)
        node = _require_node(graph, params.dep_id, kind="dependency")
        entries = serialize.entrypoints_reaching_dep(reach, params.dep_id)
        return {
            "dependency": params.dep_id,
            "name": node.name,
            "version": node.attrs.get("version"),
            "verdict": serialize.dep_verdict(reach, params.dep_id),
            "reachable": params.dep_id in serialize.reachable_dep_ids(reach),
            "entrypoints": entries,
        }

    return _safe(impl)


# -- Capability 2: DISCUSS PROBLEMS -------------------------------------------


def _finding_cvss(f: Any) -> Any:
    return f.cvss_score if f.cvss_score is not None else f.cvss_vector


def _run_advisory(repo_abspath: str, graph: Any, findings: list[Any], reach: Any, *, offline: bool):
    """Build the triage + usage lists used by audit/finding_detail.

    ``investigate_usage`` re-walks the repo filesystem for textual evidence, so
    it needs the real absolute repo path.
    """
    client = state.build_client(offline)
    triage = triage_findings(graph, findings, reach, client=client)
    usage = investigate_usage(repo_abspath, graph, findings, reach, client=client)
    return triage, usage


@mcp.tool(name="vulnreach_audit", annotations={"title": "Audit (ranked findings)", **_READ_ONLY_NETWORK})
def vulnreach_audit(params: AuditInput) -> str:
    """The headline "what's wrong" tool: ranked, reachability-aware vulnerability findings.

    Correlates dependencies against public advisory data (OSV/KEV/EPSS), joins
    reachability, and (when explain) adds advisory triage + usage evidence.
    Findings are ranked with reachable + actively-exploited first. Works with no
    API key (offline heuristic for the advisory tiers).

    Args:
        params.repo_path (str): Local repo root.
        params.offline (bool): Skip all network + model; returns no findings offline.
        params.explain (bool): Add triage/usage per finding (default True).
        params.refresh (bool): Re-scan and re-correlate.

    Returns (JSON):
        {"repo","offline":bool,"network_ok":bool,"notices":[str],
         "counts":{"findings":int,"reachable":int},
         "findings":[{"dependency","dependency_id","version","ecosystem","vuln_id",
            "cve_ids":[str],"severity","cvss","kev":bool,"epss","reachable":bool,
            "verdict","example_path":[id],"reachable_entrypoints":[str],
            "triage":{"affected","confidence","rationale"}?,
            "usage":{"usage_kind","summary"}?}]}

    Use when: you want the prioritized vulnerability list for a repo.
    Don't use when: you need one dep's full CVE text (use vulnreach_finding_detail).
    """
    def impl() -> dict[str, Any]:
        key = state.resolve_repo(params.repo_path)
        graph, corr = state.get_correlation(
            params.repo_path, offline=params.offline, refresh=params.refresh
        )
        _, reach = state.get_reachability(params.repo_path)
        report.join_reachability(graph, corr.findings, reach)
        ranked = report.rank_findings(corr.findings)

        triage_idx: dict[tuple[str, str | None], Any] = {}
        usage_idx: dict[str, Any] = {}
        if params.explain and ranked:
            triage, usage = _run_advisory(key, graph, corr.findings, reach, offline=params.offline)
            triage_idx = {(t.dependency_id, t.vuln_id): t for t in triage}
            usage_idx = {u.dependency_id: u for u in usage}

        findings_out = []
        for f in ranked:
            row: dict[str, Any] = {
                "dependency": f.dependency_name,
                "dependency_id": f.dependency_id,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "vuln_id": f.vuln_id,
                "cve_ids": f.cve_ids,
                "severity": f.severity,
                "cvss": _finding_cvss(f),
                "kev": f.kev,
                "epss": f.epss,
                "reachable": f.reachable,
                "verdict": reach.repo.verdict_by_dep.get(f.dependency_id),
                "example_path": f.example_path,
                "reachable_entrypoints": f.reachable_entrypoints,
            }
            if params.explain:
                t = triage_idx.get((f.dependency_id, f.vuln_id))
                if t is not None:
                    row["triage"] = {
                        "affected": t.affected,
                        "confidence": t.confidence,
                        "rationale": serialize.clip(t.rationale),
                    }
                u = usage_idx.get(f.dependency_id)
                if u is not None:
                    row["usage"] = {"usage_kind": u.usage_kind, "summary": serialize.clip(u.summary)}
            findings_out.append(row)

        return {
            "repo": key,
            "offline": corr.offline,
            "network_ok": corr.network_ok,
            "notices": corr.notices,
            "counts": {
                "findings": len(ranked),
                "reachable": sum(1 for f in ranked if f.reachable),
            },
            "findings": findings_out,
        }

    return _safe(impl)


@mcp.tool(name="vulnreach_finding_detail", annotations={"title": "Finding detail", **_READ_ONLY_NETWORK})
def vulnreach_finding_detail(params: FindingDetailInput) -> str:
    """Deep dive on ONE vulnerable dependency -- "discuss this problem".

    Args:
        params.repo_path (str): Local repo root.
        params.dep_id (str): The dependency node id.
        params.offline (bool): Skip network + model.

    Returns (JSON):
        {"dependency","dependency_id","version","ecosystem","reachable":bool,"verdict",
         "reaching_entrypoints":[{"entrypoint","label","example_path":[id]}],
         "cves":[{"vuln_id","cve_ids":[str],"summary","details","severity","cvss_score",
                  "cvss_vector","kev","epss","epss_percentile","fixed_versions":[str]}],
         "triage":[{"vuln_id","cve","affected","confidence","rationale","called_symbols":[str]}],
         "usage":{"usage_kind","summary","confidence","evidence":[...]}}

    Use when: reasoning about or explaining one dependency's vulnerabilities in depth.
    Don't use when: you want the whole repo's ranked list (use vulnreach_audit).
    """
    def impl() -> dict[str, Any]:
        key = state.resolve_repo(params.repo_path)
        graph, corr = state.get_correlation(params.repo_path, offline=params.offline)
        node = _require_node(graph, params.dep_id, kind="dependency")
        _, reach = state.get_reachability(params.repo_path)
        report.join_reachability(graph, corr.findings, reach)
        dep_findings = [f for f in corr.findings if f.dependency_id == params.dep_id]
        if not dep_findings:
            raise ToolError(
                f"dependency {params.dep_id!r} has no findings "
                f"({'offline mode returns none' if corr.offline else 'no known advisories'}). "
                "Run vulnreach_audit to see which deps have findings."
            )
        triage, usage = _run_advisory(key, graph, dep_findings, reach, offline=params.offline)
        usage_row = next((u for u in usage if u.dependency_id == params.dep_id), None)
        return {
            "dependency": node.name,
            "dependency_id": params.dep_id,
            "version": node.attrs.get("version"),
            "ecosystem": node.attrs.get("ecosystem"),
            "reachable": params.dep_id in serialize.reachable_dep_ids(reach),
            "verdict": serialize.dep_verdict(reach, params.dep_id),
            "reaching_entrypoints": serialize.entrypoints_reaching_dep(reach, params.dep_id),
            "cves": [
                {
                    "vuln_id": f.vuln_id,
                    "cve_ids": f.cve_ids,
                    "summary": serialize.clip(f.summary),
                    "details": serialize.clip(f.details),
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "kev": f.kev,
                    "epss": f.epss,
                    "epss_percentile": f.epss_percentile,
                    "fixed_versions": f.fixed_versions,
                }
                for f in dep_findings
            ],
            "triage": [
                {
                    "vuln_id": t.vuln_id,
                    "cve": t.cve,
                    "affected": t.affected,
                    "confidence": t.confidence,
                    "rationale": serialize.clip(t.rationale),
                    "called_symbols": t.called_symbols,
                }
                for t in triage
            ],
            "usage": None
            if usage_row is None
            else {
                "usage_kind": usage_row.usage_kind,
                "summary": serialize.clip(usage_row.summary),
                "confidence": usage_row.confidence,
                "evidence": usage_row.evidence,
            },
        }

    return _safe(impl)


# -- Capability 3: FIX --------------------------------------------------------


def _remediation_for_dep(graph: Any, reach: Any, dep_findings: list[Any], dep_id: str) -> dict[str, Any]:
    node = graph.get_node(dep_id)
    name = node.name if node else dep_id
    version = node.attrs.get("version") if node else None
    ecosystem = node.attrs.get("ecosystem") if node else None
    source_file = node.attrs.get("source_file") if node else None
    recommended = upgrade.recommend_fixed_version([f.fixed_versions for f in dep_findings])
    fixed_union = sorted({v for f in dep_findings for v in f.fixed_versions})
    cve_union = sorted({c for f in dep_findings for c in f.cve_ids})
    reachable = dep_id in serialize.reachable_dep_ids(reach)
    return {
        "dependency": name,
        "dependency_id": dep_id,
        "current_version": version,
        "current_spec": f"{name}=={version}" if version else name,
        "ecosystem": ecosystem,
        "source_file": source_file,
        "recommended_version": recommended,
        "fixed_versions": fixed_union,
        "cve_ids": cve_union,
        "kev": any(f.kev for f in dep_findings),
        "reachable": reachable,
        "verdict": serialize.dep_verdict(reach, dep_id),
        "reaching_entrypoints": serialize.entrypoints_reaching_dep(reach, dep_id),
        "next_step": (
            None
            if recommended is None
            else f"vulnreach_apply_upgrade(dep_id='{dep_id}', version='{recommended}')"
        ),
    }


@mcp.tool(name="vulnreach_remediation", annotations={"title": "Remediation plan", **_READ_ONLY_NETWORK})
def vulnreach_remediation(params: RemediationInput) -> str:
    """Everything needed to fix a vulnerable dependency without reading files.

    For one dep (dep_id) or ALL vulnerable deps: current version, the smallest
    fixed version that clears every CVE, the manifest file + current spec to
    change, reachability (priority), and the entrypoints/paths to re-test after
    upgrading. Items are ordered reachable-first.

    Args:
        params.repo_path (str): Local repo root.
        params.dep_id (str | None): One dependency, or omit for all vulnerable deps.
        params.offline (bool): Skip network + model.

    Returns (JSON):
        {"repo","offline","network_ok","count":int,
         "remediations":[{"dependency","dependency_id","current_version","current_spec",
            "ecosystem","source_file","recommended_version","fixed_versions":[str],
            "cve_ids":[str],"kev":bool,"reachable":bool,"verdict",
            "reaching_entrypoints":[{"entrypoint","label","example_path"}],"next_step"}]}

    Use when: planning upgrades; feed next_step into vulnreach_apply_upgrade.
    Don't use when: you only want to discuss severity (use vulnreach_finding_detail).
    """
    def impl() -> dict[str, Any]:
        key = state.resolve_repo(params.repo_path)
        graph, corr = state.get_correlation(params.repo_path, offline=params.offline)
        _, reach = state.get_reachability(params.repo_path)
        report.join_reachability(graph, corr.findings, reach)

        by_dep: dict[str, list[Any]] = {}
        for f in corr.findings:
            by_dep.setdefault(f.dependency_id, []).append(f)

        if params.dep_id is not None:
            _require_node(graph, params.dep_id, kind="dependency")
            if params.dep_id not in by_dep:
                raise ToolError(
                    f"dependency {params.dep_id!r} has no findings to remediate "
                    f"({'offline mode returns none' if corr.offline else 'no known advisories'})."
                )
            target_ids = [params.dep_id]
        else:
            target_ids = list(by_dep.keys())

        rems = [_remediation_for_dep(graph, reach, by_dep[d], d) for d in target_ids]
        rems.sort(key=lambda r: (0 if r["reachable"] else 1, 0 if r["kev"] else 1, r["dependency"]))
        return {
            "repo": key,
            "offline": corr.offline,
            "network_ok": corr.network_ok,
            "count": len(rems),
            "remediations": rems,
        }

    return _safe(impl)


@mcp.tool(
    name="vulnreach_apply_upgrade",
    annotations={
        "title": "Apply manifest upgrade",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def vulnreach_apply_upgrade(params: ApplyUpgradeInput) -> str:
    """Surgically re-pin ONE dependency in its manifest; returns a unified diff.

    Locates the single, unambiguous pin for the dependency in its declared
    manifest (requirements*.txt / pyproject.toml ``name==x.y.z``; package.json
    exact ``"name": "x.y.z"``) and rewrites only that version token. If it cannot
    find exactly one safe pin (none, several, or a range), it REFUSES with a
    message naming the file/line so you can edit manually. dry_run=True (default)
    previews the diff only; dry_run=False writes the file.

    Args:
        params.repo_path (str): Local repo root.
        params.dep_id (str): The dependency node id to re-pin.
        params.version (str): The exact version to pin to.
        params.dry_run (bool): True previews only (default); False writes the file.

    Returns (JSON):
        {"dependency_id","source_file","line":int,"version","dry_run":bool,
         "applied":bool,"diff":str}

    Use when: applying a remediation (after vulnreach_remediation).
    Don't use when: the pin is a range or ambiguous -- the tool will tell you to edit by hand.
    """
    def impl() -> dict[str, Any]:
        key, graph = state.get_graph(params.repo_path)
        node = _require_node(graph, params.dep_id, kind="dependency")
        plan = upgrade.plan_upgrade(key, node, params.version)
        applied = False
        if not params.dry_run:
            upgrade.write_upgrade(plan["abspath"], plan["new_text"])
            applied = True
            # The manifest changed on disk; invalidate the cached graph.
            state.get_graph(params.repo_path, refresh=True)
        return {
            "dependency_id": params.dep_id,
            "source_file": plan["source_file"],
            "line": plan["line"],
            "version": params.version,
            "dry_run": params.dry_run,
            "applied": applied,
            "diff": plan["diff"],
        }

    return _safe(impl)


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def main(argv: list[str] | None = None) -> None:
    """Console entry point: run the vulnreach MCP server over stdio or HTTP."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="vulnreach-mcp",
        description="Run the vulnreach MCP server. Defaults to stdio; wire it into "
        "an MCP client, e.g. `claude mcp add vulnreach -- vulnreach-mcp`. The "
        "streamable-http transport has no authentication of its own: run it "
        "behind a reverse proxy that enforces it.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="MCP transport (default: stdio). streamable-http serves /mcp.",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)."
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="HTTP port (default: 8000)."
    )
    args = parser.parse_args(argv)

    if args.transport == "streamable-http":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        if args.host not in _LOOPBACK_HOSTS:
            # FastMCP was constructed with its loopback default, which restricts
            # the Host header to localhost. Drop that check, as FastMCP itself
            # does when constructed with a non-loopback host.
            mcp.settings.transport_security = None
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
