"""Join findings with reachability, rank them, and render the audit report.

This module performs no network I/O. It takes the correlator's findings plus
the pure reachability result and produces the ranked, human- and
machine-readable "full scan" output.

Ranking (highest priority first): KEV, then EPSS (desc), then reachability,
then CVSS/severity (desc). The headline signal is therefore a finding that is
both actively exploited (or high-EPSS) *and* reachable from a public entry
point -- it sorts to the top.
"""

from __future__ import annotations

from typing import Any

from ..coverage import CoverageReport, compute_coverage
from ..graph import KnowledgeGraph
from ..reachability import ReachabilityResult
from . import CorrelationResult, Finding

# Ordinal weight for a severity label when no numeric CVSS score is available.
_SEVERITY_RANK: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MODERATE": 5.5,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "NONE": 0.0,
}


def _severity_number(finding: Finding) -> float:
    """A single comparable severity magnitude (numeric CVSS, else label rank)."""
    if finding.cvss_score is not None:
        return finding.cvss_score
    if finding.severity:
        return _SEVERITY_RANK.get(finding.severity.upper(), 0.0)
    return 0.0


def join_reachability(
    graph: KnowledgeGraph, findings: list[Finding], reach: ReachabilityResult
) -> None:
    """Mark each finding reachable (and record entry points / an example path).

    A finding is reachable when its dependency id appears in the repo-wide
    reachable set. The reaching entry points and a shortest example path are
    taken from the per-entrypoint reachability records.
    """
    reachable_ids = {dep["id"] for dep in reach.repo.reachable_deps}

    # dep id -> list of (entrypoint label, example path)
    routes: dict[str, list[tuple[str, list[str]]]] = {}
    for ep in reach.entrypoints:
        label = f"{ep.method} {ep.path}"
        for dep in ep.reachable_dependencies:
            routes.setdefault(dep.id, []).append((label, list(dep.example_path)))

    for finding in findings:
        if finding.dependency_id not in reachable_ids:
            continue
        finding.reachable = True
        entries = routes.get(finding.dependency_id, [])
        finding.reachable_entrypoints = sorted({label for label, _ in entries})
        if entries:
            # Shortest example path is the clearest evidence.
            finding.example_path = min((path for _, path in entries), key=len)


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted by priority (see module docstring)."""
    return sorted(
        findings,
        key=lambda f: (
            1 if f.kev else 0,
            f.epss if f.epss is not None else -1.0,
            1 if f.reachable else 0,
            _severity_number(f),
        ),
        reverse=True,
    )


def build_summary(graph: KnowledgeGraph, findings: list[Finding]) -> dict[str, Any]:
    """Compute the headline counters for the report header."""
    vulnerable_deps = {f.dependency_id for f in findings}
    return {
        "total_dependencies": len(graph.nodes_of_kind("dependency")),
        "vulnerable_dependencies": len(vulnerable_deps),
        "total_vulnerabilities": len(findings),
        "reachable_vulnerabilities": sum(1 for f in findings if f.reachable),
        "kev_vulnerabilities": sum(1 for f in findings if f.kev),
        "high_epss_vulnerabilities": sum(
            1 for f in findings if f.epss is not None and f.epss >= 0.5
        ),
    }


def audit(
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
) -> dict[str, Any]:
    """Run the join + ranking and return a JSON-serializable audit payload."""
    join_reachability(graph, correlation.findings, reach)
    ranked = rank_findings(correlation.findings)
    verdicts = reach.repo.verdict_by_dep

    def _finding_dict(finding: Finding) -> dict[str, Any]:
        payload = finding.to_dict()
        # Expose the three-way reachability verdict (reachable /
        # potentially_reachable / unreachable) that the text report already shows.
        payload["verdict"] = verdicts.get(finding.dependency_id) or (
            "reachable" if finding.reachable else "unreachable"
        )
        return payload

    return {
        "offline": correlation.offline,
        "network_ok": correlation.network_ok,
        "notices": list(correlation.notices),
        "summary": build_summary(graph, ranked),
        "coverage": compute_coverage(graph, reach).to_dict(),
        "findings": [_finding_dict(f) for f in ranked],
    }


# -- text rendering -----------------------------------------------------------


def _severity_text(finding: Finding) -> str:
    """Render the severity cell: label plus numeric score/vector when present."""
    label = finding.severity or "UNKNOWN"
    if finding.cvss_score is not None:
        return f"{label} (CVSS {finding.cvss_score:.1f} via {finding.cvss_source})"
    if finding.cvss_vector:
        return f"{label} ({finding.cvss_vector})"
    return label


def _reach_text(finding: Finding, verdict: str | None = None) -> str:
    """Render the reachability cell for one finding.

    ``verdict`` is the dependency's three-way reachability verdict
    (``reachable`` / ``potentially_reachable`` / ``unreachable``) from
    :class:`~scanner.reachability.RepoReachability.verdict_by_dep`. When given,
    the not-reachable branch distinguishes an honest, fully-resolved
    "unreachable" from a conservative "potentially reachable". When omitted the
    original wording is preserved.
    """
    if finding.reachable:
        via = ", ".join(finding.reachable_entrypoints) or "a public entry point"
        path = " -> ".join(finding.example_path)
        text = f"REACHABLE via {via}"
        if path:
            text += f"  [{path}]"
        return text
    if verdict == "potentially_reachable":
        return (
            "potentially reachable: no resolved path reaches it, but unresolved "
            "call paths on the reachable frontier could (unknown call paths)"
        )
    if verdict == "unreachable":
        return "not reachable from a public entry point (reachable call graph fully resolved)"
    return "not reachable from a public entry point"


def format_report(
    repo_path: str,
    graph: KnowledgeGraph,
    correlation: CorrelationResult,
    reach: ReachabilityResult,
) -> str:
    """Render the full ranked audit as a human-readable text report."""
    join_reachability(graph, correlation.findings, reach)
    ranked = rank_findings(correlation.findings)
    summary = build_summary(graph, ranked)

    lines: list[str] = []
    lines.append(f"vulnreach audit: {repo_path}")
    lines.append("=" * 72)

    # Degraded-mode banner (offline or network failure).
    for notice in correlation.notices:
        lines.append(f"! {notice}")
    if correlation.notices:
        lines.append("")

    lines.append("Summary")
    lines.append(f"  dependencies scanned:          {summary['total_dependencies']}")
    lines.append(f"  vulnerable dependencies:       {summary['vulnerable_dependencies']}")
    lines.append(f"  total vulnerabilities:         {summary['total_vulnerabilities']}")
    lines.append(f"  reachable vulnerabilities:     {summary['reachable_vulnerabilities']}")
    lines.append(f"  actively exploited (KEV):      {summary['kev_vulnerabilities']}")
    lines.append(f"  high EPSS (>= 0.5):            {summary['high_epss_vulnerabilities']}")
    lines.append("")

    lines.extend(_coverage_block(compute_coverage(graph, reach)))
    lines.append("")

    if not correlation.network_ok:
        lines.append(
            "Vulnerability data was not available (see notice above). Showing the "
            "dependency and reachability picture only:"
        )
        lines.append("")
        lines.extend(_reachability_block(reach))
        return "\n".join(lines)

    if not ranked:
        lines.append("No known vulnerabilities matched the resolved dependencies.")
        lines.append("")
        lines.extend(_reachability_block(reach))
        return "\n".join(lines)

    lines.append("Findings (highest priority first)")
    lines.append("-" * 72)
    verdicts = reach.repo.verdict_by_dep
    for index, finding in enumerate(ranked, start=1):
        cves = ", ".join(finding.cve_ids) or finding.vuln_id
        kev_badge = "  [KEV: actively exploited]" if finding.kev else ""
        epss_text = (
            f"EPSS {finding.epss:.3f}"
            + (f" (p{finding.epss_percentile:.2f})" if finding.epss_percentile is not None else "")
            if finding.epss is not None
            else "EPSS n/a"
        )
        lines.append(
            f"{index:>2}. {finding.dependency_name} {finding.version} "
            f"[{finding.ecosystem}] -- {cves}{kev_badge}"
        )
        lines.append(f"    severity: {_severity_text(finding)}   {epss_text}")
        lines.append(f"    {_reach_text(finding, verdicts.get(finding.dependency_id))}")
        if finding.fixed_versions:
            lines.append(f"    fixed in: {', '.join(finding.fixed_versions)}")
        if finding.summary:
            lines.append(f"    {finding.summary}")
        lines.append("")

    lines.append("EPSS data courtesy of FIRST.org (https://www.first.org/epss/).")
    return "\n".join(lines)


def _coverage_block(coverage: CoverageReport) -> list[str]:
    """Render the coverage / confidence section of the audit report.

    A quantitative summary of how much of the code the analysis actually
    resolved, so the "reachability is a lower bound" honesty is concrete.
    """
    files = coverage.files
    functions = coverage.functions
    call_sites = coverage.call_sites
    entrypoints = coverage.entrypoints
    deps = coverage.dependencies

    lines: list[str] = ["Coverage / confidence"]
    lines.append(
        f"  files parsed:                  {files.parsed}/{files.total} "
        f"({files.parse_success_rate:.0%} parsed, {files.parse_errors} failed)"
    )
    lines.append(f"  functions analyzed:            {functions.total}")
    lines.append(
        f"  call sites resolved:           {call_sites.resolved}/"
        f"{call_sites.resolved + call_sites.unresolved} "
        f"({call_sites.resolution_rate:.0%} resolved, "
        f"{call_sites.unresolved} unresolved)"
    )
    lines.append(
        f"  entry points:                  {entrypoints.total} "
        f"({entrypoints.unresolved_routes} unresolved route(s), "
        f"{entrypoints.without_handler} without a resolved handler)"
    )
    lines.append(
        f"  dependencies with a call site: {deps.with_call_site}/{deps.total}"
    )
    if deps.verdict_breakdown is not None:
        lines.append(
            f"  verdicts:                      "
            f"{deps.verdict_breakdown['reachable']} reachable, "
            f"{deps.verdict_breakdown['potentially_reachable']} potentially, "
            f"{deps.verdict_breakdown['unreachable']} unreachable"
        )
    lines.append(f"  confidence: {coverage.confidence_note}")
    return lines


def _reachability_block(reach: ReachabilityResult) -> list[str]:
    """A compact reachability recap, reused in degraded and clean-scan modes."""
    lines: list[str] = ["Reachability (dependencies reachable from a public entry point):"]
    if reach.repo.reachable_deps:
        for dep in reach.repo.reachable_deps:
            lines.append(f"  - {dep['name']} {dep['version']} [{dep['ecosystem']}]")
    else:
        lines.append("  (none)")

    # Three-way verdict recap (additive). "unreachable" is only honest when the
    # whole reachable region is fully resolved; otherwise non-reached deps are
    # "potentially reachable" because an unresolved call could still reach them.
    counts = reach.repo.verdict_counts
    if counts:
        lines.append("")
        lines.append("Three-way verdict (per declared dependency):")
        lines.append(f"  reachable:              {counts.get('reachable', 0)}")
        lines.append(f"  potentially reachable:  {counts.get('potentially_reachable', 0)}")
        lines.append(f"  unreachable:            {counts.get('unreachable', 0)}")
        if not reach.repo.reachable_region_fully_resolved:
            lines.append(
                "  note: the reachable call graph contains unresolved call sites, so "
                "non-reached deps are reported as potentially reachable, not unreachable."
            )
    return lines
