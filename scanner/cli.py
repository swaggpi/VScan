"""Command-line interface: ``scan``, ``reachability`` and ``audit``.

``scan`` builds the knowledge graph for a target repository, writes it as JSON,
and prints a human-readable summary to stderr. ``reachability`` builds the same
graph, computes which public entry points reach which functions and
dependencies, and prints a readable report (or JSON). ``audit`` is the headline
"full scan": it correlates the dependency graph against public vulnerability
databases and joins the findings with reachability to produce a ranked report.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .agent import LLMClient, assess_findings, investigate_usage, triage_findings
from .correlate import CorrelationResult, correlate_full
from .correlate import report as correlate_report
from .coverage import compute_coverage
from .dotenv import load_dotenv
from .graph import KnowledgeGraph
from .reachability import ReachabilityResult, compute_reachability
from .scan import scan_repo

_DEFAULT_OUTPUT = "vulnreach-graph.json"


def _print_summary(graph: KnowledgeGraph, repo_path: str, output_path: str) -> None:
    summary = graph.summary()
    node_counts = summary["node_counts"]
    deps = summary["dependencies"]

    out = sys.stderr
    print(f"vulnreach scan: {repo_path}", file=out)
    print(f"  files:        {node_counts.get('file', 0)}", file=out)
    print(f"  modules:      {node_counts.get('module', 0)}", file=out)
    print(f"  functions:    {node_counts.get('function', 0)}", file=out)
    print(f"  entrypoints:  {node_counts.get('entrypoint', 0)}", file=out)
    print(f"  docs:         {node_counts.get('doc', 0)}", file=out)
    print(f"  dependencies: {len(deps)}", file=out)

    if deps:
        print("\n  Dependencies:", file=out)
        for dep in deps:
            marker = "resolved" if dep["resolved"] else "declared"
            print(
                f"    - [{dep['ecosystem']}] {dep['name']} "
                f"{dep['version']} ({marker})",
                file=out,
            )

    entrypoints = graph.nodes_of_kind("entrypoint")
    if entrypoints:
        print("\n  Entry points:", file=out)
        for ep in sorted(entrypoints, key=lambda n: n.id):
            handler = ep.attrs.get("handler", "?")
            print(
                f"    - {ep.attrs.get('method', '?')} {ep.attrs.get('path', '?')} "
                f"-> {handler}",
                file=out,
            )

    cov = compute_coverage(graph)
    print("\n  Coverage / confidence:", file=out)
    print(
        f"    files parsed:        {cov.files.parsed}/{cov.files.total} "
        f"({cov.files.parse_success_rate:.0%})",
        file=out,
    )
    print(
        f"    call sites resolved: {cov.call_sites.resolved}/"
        f"{cov.call_sites.resolved + cov.call_sites.unresolved} "
        f"(~{cov.call_sites.resolution_rate:.0%})",
        file=out,
    )
    print(f"    entry points:        {cov.entrypoints.total}", file=out)

    print(f"\n  Graph written to: {output_path}", file=out)


def _format_reachability(result: ReachabilityResult, repo_path: str) -> str:
    """Render a reachability result as a human-readable text report."""
    lines: list[str] = []
    lines.append(f"vulnreach reachability: {repo_path}")
    lines.append("")

    if not result.entrypoints:
        lines.append("No public entry points found.")
    for ep in result.entrypoints:
        handlers = ", ".join(ep.handlers) if ep.handlers else "(no resolved handler)"
        lines.append(f"{ep.method} {ep.path} -> {handlers}")
        lines.append(f"  reachable functions: {ep.reachable_function_count}")
        if ep.reachable_dependencies:
            lines.append("  reachable dependencies:")
            for dep in ep.reachable_dependencies:
                symbol = dep.symbol or "?"
                lines.append(
                    f"    - {dep.name} {dep.version} [{dep.ecosystem}]  "
                    f"(called via {symbol})"
                )
                lines.append(f"      example path: {' -> '.join(dep.example_path)}")
        else:
            lines.append("  reachable dependencies: none")
        lines.append(
            f"  unresolved calls encountered: {ep.unresolved_calls_encountered} "
            "(reachability is a lower bound -- unresolved call sites are never "
            "turned into edges)"
        )
        lines.append("")

    repo = result.repo
    lines.append("Dependencies reachable from a public entry point:")
    if repo.reachable_deps:
        for dep in repo.reachable_deps:
            lines.append(
                f"  - {dep['name']} {dep['version']} [{dep['ecosystem']}]"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    # Non-reached deps, split by the sound three-way verdict. ``unreachable_deps``
    # is declared-minus-reached (binary); the verdict says whether that absence
    # is trustworthy (region fully resolved) or merely unproven.
    no_call_site = {d["id"] for d in repo.deps_without_call_site}
    verdicts = repo.verdict_by_dep
    groups = (
        (
            "potentially_reachable",
            "Potentially reachable (unresolved call paths exist):",
        ),
        (
            "unreachable",
            "Not reachable (reachable call graph fully resolved):",
        ),
    )
    first_group = True
    for verdict, header in groups:
        members = [
            d for d in repo.unreachable_deps if verdicts.get(d["id"]) == verdict
        ]
        if not members:
            continue
        if not first_group:
            lines.append("")
        first_group = False
        lines.append(header)
        for dep in members:
            note = (
                " (no resolved call site at all)" if dep["id"] in no_call_site else ""
            )
            lines.append(
                f"  - {dep['name']} {dep['version']} [{dep['ecosystem']}]{note}"
            )

    return "\n".join(lines)


def _oneline(text: str, limit: int = 300) -> str:
    """Flatten a model-derived string to a single, length-capped line.

    Collapses every run of whitespace (including newlines) to one space and
    truncates, so a ``rationale``/``summary`` the model returns -- or that it
    echoes from injected documentation -- can never forge extra report lines
    (e.g. a smuggled ``"\\n    REACHABLE via ..."``). Mirrors ``osv._short``.
    """
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def _assess_exposure(
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
    *,
    offline: bool,
) -> tuple[list, bool]:
    """Run the advisory agent pass once, returning (assessments, model_used).

    Uses the configured model when available; otherwise the deterministic
    offline heuristic. ``offline`` forces the heuristic (no network) regardless
    of whether model env vars are set, matching ``audit --offline``. The result
    is reused by the ``--explain`` text render, the ``--bundle`` payload and the
    ``--json`` audit output so the model is called at most once per run.
    """
    client = LLMClient.disabled() if offline else LLMClient()
    assessments = assess_findings(graph, correlation.findings, reach, client=client)
    return assessments, client.available()


def _format_assessments(assessments: list, *, model_configured: bool) -> str:
    """Render the advisory exposure assessments for the reachable findings."""
    lines: list[str] = ["", "Exposure assessment (advisory tier)", "-" * 72]
    if model_configured:
        lines.append("Model: configured via LLM_BASE_URL/LLM_API_KEY/LLM_MODEL.")
    else:
        lines.append(
            "Note: using the offline heuristic (no model configured). Enable the "
            "model by setting LLM_BASE_URL, LLM_API_KEY and LLM_MODEL."
        )
    lines.append(
        "This tier is ADVISORY ONLY: it does not change the reachability verdict."
    )
    lines.append("")

    if not assessments:
        lines.append("No reachable findings to assess.")
        return "\n".join(lines)

    for index, a in enumerate(assessments, start=1):
        ref = a.cve or a.vuln_id or "(no advisory id)"
        via = ", ".join(a.reaching_entrypoints) or "a public entry point"
        lines.append(f"{index:>2}. {a.dependency_name} -- {ref}")
        lines.append(f"    reachable via: {via}")
        lines.append(f"    exposure: {a.exposure}   authentication: {a.authentication}")
        lines.append(f"    rationale: {_oneline(a.rationale)}")
        lines.append(f"    summary: {_oneline(a.summary)}")
        for item in a.context:
            access = item.get("access")
            access_text = f"; access: {_oneline(str(access), 120)}" if access else ""
            lines.append(
                f"    context [{item.get('category')}] {_oneline(str(item.get('detail')), 120)}"
                f"{access_text}  (source: {item.get('source')})"
            )
            lines.append(f"      snippet: \"{_oneline(str(item.get('snippet')), 160)}\"")
        lines.append(f"    [provenance={a.provenance}; advisory={a.advisory}]")
        lines.append("")
    return "\n".join(lines)


def _triage_exploitability(
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
    *,
    offline: bool,
) -> tuple[list, bool]:
    """Run the advisory symbol-level triage pass once, returning (triage, model).

    The second agent capability: for each reachable vulnerable dependency it
    compares the dependency symbols the project actually calls against the CVE
    description and judges whether the project is actually affected. Uses the
    configured model when available; otherwise the deterministic offline
    heuristic. ``offline`` forces the heuristic (no network) regardless of the
    model env vars, matching ``audit --offline`` and ``_assess_exposure``. The
    result is reused by ``--explain``, ``--bundle`` and ``--json``/``-o`` so the
    model is called at most once per run for triage.
    """
    client = LLMClient.disabled() if offline else LLMClient()
    triage = triage_findings(graph, correlation.findings, reach, client=client)
    return triage, client.available()


def _format_triage(triage: list, *, model_configured: bool) -> str:
    """Render the advisory symbol-level exploitability triage for the findings."""
    lines: list[str] = ["", "Exploitability triage (advisory tier)", "-" * 72]
    if model_configured:
        lines.append("Model: configured via LLM_BASE_URL/LLM_API_KEY/LLM_MODEL.")
    else:
        lines.append(
            "Note: using the offline heuristic (no model configured). Enable the "
            "model by setting LLM_BASE_URL, LLM_API_KEY and LLM_MODEL."
        )
    lines.append(
        "This tier is ADVISORY ONLY and CONSERVATIVE: it compares the project's "
        "called symbols to the CVE, never changes reachability, and withholds "
        "'likely_unaffected' unless usage is fully resolved."
    )
    lines.append("")

    if not triage:
        lines.append("No reachable findings to triage.")
        return "\n".join(lines)

    for index, t in enumerate(triage, start=1):
        ref = t.cve or t.vuln_id or "(no advisory id)"
        called = ", ".join(t.called_symbols) or "no resolved symbols"
        lines.append(
            f"{index:>2}. {t.dependency_name} {ref}: "
            f"{t.affected.upper()} ({t.confidence})"
        )
        lines.append(f"    calls: {_oneline(called, 200)}")
        if t.unresolved_calls_into_dependency:
            lines.append("    note: unresolved calls into this dependency (usage view incomplete)")
        lines.append(f"    rationale: {_oneline(t.rationale)}")
        lines.append(f"    [provenance={t.provenance}; advisory={t.advisory}]")
        lines.append("")
    return "\n".join(lines)


def _investigate_usage(
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
    repo_path: str,
    *,
    offline: bool,
) -> tuple[list, bool]:
    """Run the advisory dynamic-usage investigation once, returning (usage, model).

    The third agent capability: for each VULNERABLE dependency with NO statically
    resolved call into it -- the "no static resolving" set the triage tier cannot
    cover -- it gathers deterministic textual evidence from the repo (``repo_path``
    is needed to re-walk the files) and classifies where/how it is actually used
    (dynamic import, config/infra, transitive, dev/build). Uses the configured
    model when available; otherwise the deterministic offline heuristic.
    ``offline`` forces the heuristic (no network) regardless of the model env
    vars, matching ``_assess_exposure`` / ``_triage_exploitability``. The result
    is reused by ``--explain``, ``--bundle`` and ``--json``/``-o`` so the model is
    called at most once per target dep per run.
    """
    client = LLMClient.disabled() if offline else LLMClient()
    usage = investigate_usage(repo_path, graph, correlation.findings, reach, client=client)
    return usage, client.available()


def _format_usage(usage: list, *, model_configured: bool) -> str:
    """Render the advisory dynamic-usage investigation for unresolved deps."""
    lines: list[str] = ["", "Dynamic-usage investigation (advisory tier)", "-" * 72]
    if model_configured:
        lines.append("Model: configured via LLM_BASE_URL/LLM_API_KEY/LLM_MODEL.")
    else:
        lines.append(
            "Note: using the offline heuristic (no model configured). Enable the "
            "model by setting LLM_BASE_URL, LLM_API_KEY and LLM_MODEL."
        )
    lines.append(
        "This tier is ADVISORY ONLY: for vulnerable deps with NO resolved static "
        "call, it describes WHERE/HOW they are used (dynamic import, config/infra, "
        "transitive, dev/build). It never changes reachability and never claims a "
        "dependency is unused or safe."
    )
    lines.append("")

    if not usage:
        lines.append("No unresolved vulnerable dependencies to investigate.")
        return "\n".join(lines)

    for index, u in enumerate(usage, start=1):
        ref = ", ".join(u.cves) or "(no advisory id)"
        lines.append(
            f"{index:>2}. {u.dependency_name} {u.version or ''} [{ref}]: "
            f"{u.usage_kind.upper()} ({u.confidence})"
        )
        searched = ", ".join(u.import_names) or u.dependency_name
        lines.append(f"    searched: {_oneline(searched, 200)}")
        if u.evidence:
            top = u.evidence[0]
            lines.append(
                f"    evidence: {len(u.evidence)} hit(s), e.g. "
                f"{top['source']}:{top['line']}"
            )
        else:
            lines.append("    evidence: none found (likely transitive/indirect)")
        lines.append(f"    summary: {_oneline(u.summary)}")
        lines.append(f"    [provenance={u.provenance}; advisory={u.advisory}]")
        lines.append("")
    return "\n".join(lines)


def _build_bundle(
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
    *,
    assessments: list,
    triage: list,
    usage: list,
) -> dict:
    """Assemble one self-contained payload the dashboard viewer can load.

    Reuses the ranked audit payload -- findings carry the reachable flag, the
    three-way verdict, cve/severity/kev/epss and an example path, plus the
    headline summary and network status -- and adds the structural graph and
    the full reachability result so the viewer needs no other file. Works
    offline too: findings is then empty and ``offline``/``network_ok`` say so.

    ``assessments`` is the advisory exposure tier and ``triage`` the advisory
    symbol-level exploitability tier (both already computed by the caller with
    the real model when configured, else the offline heuristic). They are
    surfaced under ``"assessments"`` and ``"triage"`` so the viewer can attach
    each exposure/auth judgement and each affected/likely_unaffected/uncertain
    judgement to the matching finding / entry point. ``usage`` is the advisory
    dynamic-usage tier -- for each vulnerable dep with NO resolved static call,
    where/how it is actually used -- surfaced under ``"usage"``. The bundle
    therefore ALWAYS carries all three tiers (offline-grounded by default).
    """
    audit_payload = correlate_report.audit(
        graph, correlation, reach, assessments=assessments, triage=triage, usage=usage
    )
    return {
        "graph": graph.to_dict(),
        "reachability": reach.to_dict(),
        "findings": audit_payload["findings"],
        "summary": audit_payload["summary"],
        "coverage": audit_payload["coverage"],
        "assessments": audit_payload["assessments"],
        "triage": audit_payload["triage"],
        "usage": audit_payload["usage"],
        "offline": audit_payload["offline"],
        "network_ok": audit_payload["network_ok"],
        "notices": audit_payload["notices"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        prog="vulnreach",
        description="Reachability-aware dependency scanner (layer 1: structure graph).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Scan a repository and emit its knowledge graph as JSON."
    )
    scan_parser.add_argument("repo_path", help="Path to the repository to scan.")
    scan_parser.add_argument(
        "-o",
        "--output",
        default=_DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {_DEFAULT_OUTPUT}).",
    )

    reach_parser = subparsers.add_parser(
        "reachability",
        help="Compute which entry points reach which functions and dependencies.",
    )
    reach_parser.add_argument("repo_path", help="Path to the repository to scan.")
    reach_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write the full reachability result as JSON.",
    )
    reach_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout instead of the text report.",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Full scan: correlate dependencies against vuln databases and "
        "reachability, then print a ranked report.",
    )
    audit_parser.add_argument("repo_path", help="Path to the repository to scan.")
    audit_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write the full audit result as JSON.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout instead of the text report.",
    )
    audit_parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not query any network database; still print graph + reachability.",
    )
    audit_parser.add_argument(
        "--nvd",
        action="store_true",
        help="Best-effort NVD numeric CVSS lookups (rate-limited; reads "
        "NVD_API_KEY from the environment if set).",
    )
    audit_parser.add_argument(
        "--explain",
        "--assess",
        dest="explain",
        action="store_true",
        help="Advisory LLM/offline exposure assessment of the reachable "
        "findings (opt-in; uses the offline heuristic when no model is "
        "configured via LLM_BASE_URL/LLM_API_KEY/LLM_MODEL).",
    )
    audit_parser.add_argument(
        "--bundle",
        default=None,
        metavar="PATH",
        help="Also write a self-contained viewer bundle (graph + reachability + "
        "ranked findings + summary) as one JSON file for the dashboard. Additive "
        "and opt-in: it does not affect the -o/--json output. Works offline, in "
        "which case the findings list is empty.",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            graph = scan_repo(args.repo_path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(graph.to_json())

        _print_summary(graph, args.repo_path, args.output)
        return 0

    if args.command == "reachability":
        try:
            graph = scan_repo(args.repo_path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        result = compute_reachability(graph)
        payload = json.dumps(result.to_dict(), indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(payload)

        if args.json:
            print(payload)
        else:
            print(_format_reachability(result, args.repo_path))
        return 0

    if args.command == "audit":
        try:
            graph = scan_repo(args.repo_path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        reach = compute_reachability(graph)
        correlation = correlate_full(
            graph, offline=args.offline, use_nvd=args.nvd
        )

        # The advisory agent tier feeds --bundle (always), the --json/-o audit
        # payload, and the --explain text render. Compute it once -- so the model
        # is called at most once per run -- only when something needs it. The
        # default audit TEXT output never triggers it, so defaults are unchanged.
        assessments: list = []
        triage: list = []
        usage: list = []
        model_configured = False
        if args.bundle or args.json or args.output or args.explain:
            assessments, model_configured = _assess_exposure(
                graph, correlation, reach, offline=args.offline
            )
            triage, _ = _triage_exploitability(
                graph, correlation, reach, offline=args.offline
            )
            usage, _ = _investigate_usage(
                graph, correlation, reach, args.repo_path, offline=args.offline
            )

        if args.bundle:
            with open(args.bundle, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        _build_bundle(
                            graph,
                            correlation,
                            reach,
                            assessments=assessments,
                            triage=triage,
                            usage=usage,
                        ),
                        indent=2,
                    )
                )

        if args.output or args.json:
            payload = json.dumps(
                correlate_report.audit(
                    graph, correlation, reach,
                    assessments=assessments, triage=triage, usage=usage,
                ),
                indent=2,
            )
            if args.output:
                with open(args.output, "w", encoding="utf-8") as handle:
                    handle.write(payload)
            if args.json:
                print(payload)
                return 0

        print(
            correlate_report.format_report(
                args.repo_path, graph, correlation, reach
            )
        )
        if args.explain:
            print(
                _format_assessments(assessments, model_configured=model_configured)
            )
            print(_format_triage(triage, model_configured=model_configured))
            print(_format_usage(usage, model_configured=model_configured))
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
