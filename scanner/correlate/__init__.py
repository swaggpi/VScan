"""Vulnerability correlator: the scanner's only network-touching layer.

This package matches the dependency graph produced by :mod:`scanner.scan`
against public vulnerability databases (OSV, CISA KEV, EPSS, optionally NVD) and
joins the result with reachability so the headline "full scan" can surface the
money signal: a vulnerability that is both *actively exploited / high-EPSS* and
*reachable from a public entry point*.

Isolation contract
-------------------
All network I/O lives here (in :mod:`.osv` and :mod:`.enrich`). The rest of the
scanner -- walker, analyzers, graph, reachability -- stays network-free. Every
request has a timeout and is wrapped so a failure never crashes a scan:
``offline=True`` or any OSV network failure yields an empty finding list with a
notice, so the CLI can still print the graph and reachability offline.

Public surface:

* :class:`Finding`               -- one advisory against one dependency.
* :func:`correlate`              -- graph -> list[Finding] (documented contract).
* :func:`correlate_full`         -- same, returning network status + notices too.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..graph import KnowledgeGraph
from . import enrich, osv
from .osv import DepRef

__all__ = ["Finding", "CorrelationResult", "correlate", "correlate_full"]


@dataclass
class Finding:
    """One vulnerability affecting one dependency, with correlation signals.

    JSON-serializable via :meth:`to_dict`. Reachability fields are populated by
    :func:`scanner.correlate.report.join_reachability`; they default to the
    conservative "not known reachable" state.
    """

    # Which dependency.
    dependency_id: str
    dependency_name: str
    version: str | None
    ecosystem: str | None

    # Which vulnerability.
    vuln_id: str
    cve_ids: list[str]
    summary: str
    fixed_versions: list[str]

    # Severity. ``cvss_score`` is numeric (NVD only); ``cvss_vector`` is the
    # CVSS vector string (OSV or NVD); ``severity`` is a label (CRITICAL/HIGH/..).
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_source: str | None = None  # "OSV" | "NVD" | None

    # Exploitation signals.
    kev: bool = False
    epss: float | None = None
    epss_percentile: float | None = None

    # Reachability join (filled later).
    reachable: bool = False
    reachable_entrypoints: list[str] = field(default_factory=list)
    example_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationResult:
    """Full correlator outcome: findings plus network status and notices."""

    findings: list[Finding]
    offline: bool
    network_ok: bool
    notices: list[str] = field(default_factory=list)


def _deps_from_graph(graph: KnowledgeGraph) -> list[DepRef]:
    """Project ``dependency`` graph nodes into :class:`DepRef` query inputs."""
    refs: list[DepRef] = []
    for node in graph.nodes_of_kind("dependency"):
        refs.append(
            DepRef(
                id=node.id,
                name=node.name,
                version=node.attrs.get("version"),
                ecosystem=node.attrs.get("ecosystem"),
            )
        )
    return refs


def correlate_full(
    graph: KnowledgeGraph, *, offline: bool = False, use_nvd: bool = False
) -> CorrelationResult:
    """Correlate ``graph`` against the vuln databases, reporting network status.

    When ``offline`` is set, no network call is attempted and an empty result is
    returned with a notice. If OSV itself is unreachable, findings are empty and
    ``network_ok`` is ``False`` (we cannot correlate without the advisory match).
    Enrichment failures leave findings in place but add a notice.
    """
    if offline:
        return CorrelationResult(
            findings=[],
            offline=True,
            network_ok=False,
            notices=["Offline mode: no vulnerability database was queried."],
        )

    deps = _deps_from_graph(graph)
    osv_result = osv.collect(deps)
    if not osv_result.ok:
        return CorrelationResult(
            findings=[],
            offline=False,
            network_ok=False,
            notices=[
                "OSV.dev was unreachable; vulnerability correlation skipped. "
                "The dependency graph and reachability analysis are still valid."
            ],
        )

    findings: list[Finding] = []
    for node in graph.nodes_of_kind("dependency"):
        for vuln in osv_result.by_dep.get(node.id, []):
            findings.append(
                Finding(
                    dependency_id=node.id,
                    dependency_name=node.name,
                    version=node.attrs.get("version"),
                    ecosystem=node.attrs.get("ecosystem"),
                    vuln_id=vuln.id,
                    cve_ids=list(vuln.cve_ids),
                    summary=vuln.summary,
                    fixed_versions=list(vuln.fixed_versions),
                    severity=vuln.severity_label,
                    cvss_vector=vuln.cvss_vector,
                    cvss_source="OSV" if vuln.cvss_vector else None,
                )
            )

    notices = enrich.enrich_findings(findings, use_nvd=use_nvd)
    return CorrelationResult(
        findings=findings,
        offline=False,
        network_ok=True,
        notices=notices,
    )


def correlate(
    graph: KnowledgeGraph, *, offline: bool = False, use_nvd: bool = False
) -> list[Finding]:
    """Correlate ``graph`` and return the list of findings (the core contract).

    ``offline=True`` or any OSV network failure returns ``[]`` without raising.
    Use :func:`correlate_full` when the caller also needs the network status.
    """
    return correlate_full(graph, offline=offline, use_nvd=use_nvd).findings
