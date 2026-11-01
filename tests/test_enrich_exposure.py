"""Tests for the Phase-1 advisory EXPOSURE overlay and its endpoint.

These never touch the network or require an API key: the LLM client is forced
unavailable so :func:`scanner.agent.assess_findings` runs its deterministic
offline heuristic, and the graph / reachability / correlation are hand-built.

They exercise:

* the overlay being keyed by entry point node id, every entry carrying the
  required fields with ``value`` / ``authentication`` in the allowed enums;
* ``origin == "doc"`` only when real doc citations exist, else ``"inferred"``
  (and an inferred definite claim saying so), with the confidence mapping;
* the CARDINAL RULE -- the overlay reads only, never mutating the graph or a
  finding; and
* the ``GET /api/enrichment`` endpoint's 503 (while warming) / 200 (ready)
  routing over hand-built scan state.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from scanner.correlate import CorrelationResult, Finding
from scanner.enrich.exposure import (
    _AUTH_VALUES,
    _CONFIDENCE_VALUES,
    _EXPOSURE_VALUES,
    _ORIGIN_VALUES,
    exposure_overlay,
)
from scanner.graph import KnowledgeGraph
from scanner.reachability import (
    EntrypointReachability,
    ReachabilityResult,
    ReachedDependency,
    RepoReachability,
)

# Entry point ids used across the fixtures.
EP_PUBLIC = "ep:POST:/documents/import"  # docs: public + unauthenticated
EP_INTERNAL = "ep:GET:/internal/health"  # docs: internal use only
EP_ORPHAN = "ep:GET:/orphan"  # no docs, no reachable finding
EP_WEBHOOK = "ep:POST:/webhook"  # docs linked, but no reachable finding

DEP_YAML = "dep:PyPI:PyYAML"
DEP_REQ = "dep:PyPI:requests"


class _OfflineClient:
    """A duck-typed LLM client that is never available (forces the offline path)."""

    def available(self) -> bool:
        return False

    def complete_json(self, system_prompt: str, user_prompt: str):  # pragma: no cover
        raise AssertionError("offline client must not be called")


def _ep_node(graph: KnowledgeGraph, ep_id: str, method: str, path: str) -> None:
    graph.add_node(ep_id, "entrypoint", f"{method} {path}", method=method, path=path)


def _doc_link(
    graph: KnowledgeGraph, doc_id: str, relpath: str, ep_id: str, snippet: str
) -> None:
    graph.add_node(doc_id, "doc", relpath, relpath=relpath, excerpt=snippet)
    graph.add_edge(doc_id, ep_id, "documents", snippet=snippet)


def _graph() -> KnowledgeGraph:
    g = KnowledgeGraph()
    _ep_node(g, EP_PUBLIC, "POST", "/documents/import")
    _ep_node(g, EP_INTERNAL, "GET", "/internal/health")
    _ep_node(g, EP_ORPHAN, "GET", "/orphan")
    _ep_node(g, EP_WEBHOOK, "POST", "/webhook")
    g.add_node(DEP_YAML, "dependency", "PyYAML", ecosystem="PyPI", version="5.3")
    g.add_node(DEP_REQ, "dependency", "requests", ecosystem="PyPI", version="2.19.0")
    _doc_link(
        g,
        "doc:docs/public.md",
        "docs/public.md",
        EP_PUBLIC,
        "This endpoint is publicly accessible and unauthenticated.",
    )
    _doc_link(
        g,
        "doc:docs/internal.md",
        "docs/internal.md",
        EP_INTERNAL,
        "This route is for internal use only.",
    )
    _doc_link(
        g,
        "doc:docs/webhook.md",
        "docs/webhook.md",
        EP_WEBHOOK,
        "Webhook receiver for partner events.",
    )
    return g


def _reached(dep_id: str, name: str) -> ReachedDependency:
    return ReachedDependency(
        id=dep_id,
        name=name,
        version=None,
        ecosystem="PyPI",
        symbol=None,
        symbols=[],
        example_path=[],
    )


def _reachability() -> ReachabilityResult:
    entrypoints = [
        EntrypointReachability(
            id=EP_PUBLIC,
            method="POST",
            path="/documents/import",
            handlers=[],
            reachable_function_count=0,
            reachable_dependencies=[_reached(DEP_YAML, "PyYAML")],
            unresolved_calls_encountered=0,
        ),
        EntrypointReachability(
            id=EP_INTERNAL,
            method="GET",
            path="/internal/health",
            handlers=[],
            reachable_function_count=0,
            reachable_dependencies=[_reached(DEP_REQ, "requests")],
            unresolved_calls_encountered=0,
        ),
        EntrypointReachability(
            id=EP_ORPHAN,
            method="GET",
            path="/orphan",
            handlers=[],
            reachable_function_count=0,
            reachable_dependencies=[],
            unresolved_calls_encountered=0,
        ),
        EntrypointReachability(
            id=EP_WEBHOOK,
            method="POST",
            path="/webhook",
            handlers=[],
            reachable_function_count=0,
            reachable_dependencies=[],
            unresolved_calls_encountered=0,
        ),
    ]
    repo = RepoReachability(
        reachable_deps=[
            {"id": DEP_YAML, "name": "PyYAML", "version": "5.3", "ecosystem": "PyPI"},
            {"id": DEP_REQ, "name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
        ]
    )
    return ReachabilityResult(entrypoints=entrypoints, repo=repo)


def _finding(dep_id: str, name: str, vuln_id: str) -> Finding:
    return Finding(
        dependency_id=dep_id,
        dependency_name=name,
        version="5.3",
        ecosystem="PyPI",
        vuln_id=vuln_id,
        cve_ids=[vuln_id.replace("GHSA", "CVE")],
        summary=f"A vulnerability in {name}",
        fixed_versions=["9.9"],
    )


def _correlation() -> CorrelationResult:
    return CorrelationResult(
        findings=[
            _finding(DEP_YAML, "PyYAML", "GHSA-yaml-0001"),
            _finding(DEP_REQ, "requests", "GHSA-req-0001"),
        ],
        offline=False,
        network_ok=True,
    )


def _overlay() -> dict[str, Any]:
    return exposure_overlay(_graph(), _reachability(), _correlation(), _OfflineClient())


# -- shape + enums ------------------------------------------------------------


def test_overlay_keyed_by_entrypoint_id_with_required_fields():
    overlay = _overlay()
    # Keyed by every entry point node id.
    assert set(overlay) == {EP_PUBLIC, EP_INTERNAL, EP_ORPHAN, EP_WEBHOOK}
    required = {
        "label",
        "value",
        "authentication",
        "origin",
        "confidence",
        "rationale",
        "sources",
    }
    for ep_id, entry in overlay.items():
        assert required <= set(entry), f"{ep_id} missing fields"
        assert entry["value"] in _EXPOSURE_VALUES
        assert entry["authentication"] in _AUTH_VALUES
        assert entry["origin"] in _ORIGIN_VALUES
        assert entry["confidence"] in _CONFIDENCE_VALUES
        assert isinstance(entry["sources"], list)
        for src in entry["sources"]:
            assert set(src) == {"doc", "snippet"}
            assert src["doc"] and src["snippet"]


def test_public_entrypoint_is_internet_facing_unauth_doc_grounded():
    entry = _overlay()[EP_PUBLIC]
    assert entry["label"] == "POST /documents/import"
    assert entry["value"] == "internet-facing"
    assert entry["authentication"] == "none"
    assert entry["origin"] == "doc"
    assert entry["confidence"] == "high"
    # The citation is the real doc snippet, never fabricated.
    assert entry["sources"] == [
        {
            "doc": "docs/public.md",
            "snippet": "This endpoint is publicly accessible and unauthenticated.",
        }
    ]


def test_internal_entrypoint_is_internal_doc_grounded():
    entry = _overlay()[EP_INTERNAL]
    assert entry["value"] == "internal"
    assert entry["origin"] == "doc"
    assert entry["confidence"] == "high"
    assert entry["sources"][0]["doc"] == "docs/internal.md"


# -- origin / confidence mapping ----------------------------------------------


def test_origin_inferred_only_when_no_sources():
    overlay = _overlay()
    # Doc-linked entry points cite real docs -> origin "doc".
    assert all(
        overlay[ep]["origin"] == "doc" for ep in (EP_PUBLIC, EP_INTERNAL, EP_WEBHOOK)
    )
    # The orphan has no linked docs -> origin "inferred", confidence low, unknown.
    orphan = overlay[EP_ORPHAN]
    assert orphan["sources"] == []
    assert orphan["origin"] == "inferred"
    assert orphan["value"] == "unknown"
    assert orphan["authentication"] == "unknown"
    assert orphan["confidence"] == "low"


def test_doc_linked_but_no_finding_is_unknown_low_but_cited():
    # Docs are linked yet no reachable finding flows here: honest unknown/low,
    # but the citation is still surfaced (origin stays "doc").
    entry = _overlay()[EP_WEBHOOK]
    assert entry["value"] == "unknown"
    assert entry["authentication"] == "unknown"
    assert entry["confidence"] == "low"
    assert entry["origin"] == "doc"
    assert entry["sources"][0]["doc"] == "docs/webhook.md"


def test_inferred_definite_claim_says_so_in_rationale():
    # A dependency reached from an entry point that itself has no linked doc:
    # the exposure verdict is definite but not grounded on this node, so it is
    # labelled inferred and the rationale admits it.
    g = _graph()
    # Remove the public entry point's own doc link, but keep its finding reachable
    # via a second, undocumented reaching entry point only.
    reach = _reachability()
    # Make PyYAML reachable from the ORPHAN entry point (no docs) as well, and
    # drop it from the documented public one, so its verdict is driven by the
    # (still documented, via the dep's other evidence) heuristic yet this node
    # cites nothing.
    reach.entrypoints[2].reachable_dependencies = [_reached(DEP_YAML, "PyYAML")]
    reach.entrypoints[0].reachable_dependencies = [_reached(DEP_YAML, "PyYAML")]
    overlay = exposure_overlay(g, reach, _correlation(), _OfflineClient())
    orphan = overlay[EP_ORPHAN]
    # PyYAML's assessment (driven by the public doc) is internet-facing; attributed
    # to the orphan node it has no local citation -> inferred + honest clause.
    assert orphan["value"] == "internet-facing"
    assert orphan["origin"] == "inferred"
    assert orphan["confidence"] == "medium"
    assert "inferred" in orphan["rationale"].lower()


def test_shared_dep_internal_route_not_overclaimed_as_documented():
    # An INTERNAL route shares a vulnerable dependency with a PUBLIC one. The
    # dependency's exposure is judged internet-facing from the PUBLIC route's
    # docs, but that verdict must NOT be presented as the internal route's OWN
    # documented exposure (the over-claim the review found): the internal node
    # caps at inferred/medium and the rationale says where it came from.
    g = _graph()
    reach = _reachability()
    # requests (DEP_REQ) is now reachable from BOTH the public and internal EPs,
    # so a single dependency-group assessment covers both routes.
    reach.entrypoints[0].reachable_dependencies = [_reached(DEP_REQ, "requests")]
    reach.entrypoints[1].reachable_dependencies = [_reached(DEP_REQ, "requests")]
    overlay = exposure_overlay(g, reach, _correlation(), _OfflineClient())

    public = overlay[EP_PUBLIC]
    internal = overlay[EP_INTERNAL]

    # Both inherit the group's internet-facing verdict ...
    assert public["value"] == "internet-facing"
    assert internal["value"] == "internet-facing"
    # ... but only the PUBLIC route's OWN docs state it -> doc-grounded, high.
    assert public["origin"] == "doc"
    assert public["confidence"] == "high"
    # The INTERNAL route's own docs ("internal use only") do NOT support the
    # internet-facing value: never "doc-cited / high", only inferred / medium.
    assert internal["origin"] == "inferred"
    assert internal["confidence"] == "medium"
    rationale = internal["rationale"].lower()
    assert "inferred" in rationale and "another route" in rationale
    # Its own real citation is still surfaced (we did not drop the evidence).
    assert internal["sources"][0]["doc"] == "docs/internal.md"


# -- cardinal rule: no mutation ----------------------------------------------


def test_overlay_does_not_mutate_graph_or_findings():
    graph = _graph()
    reachability = _reachability()
    correlation = _correlation()

    nodes_before = {
        n.id: (n.kind, n.name, copy.deepcopy(n.attrs)) for n in graph.nodes
    }
    edges_before = [
        (e.src, e.dst, e.kind, copy.deepcopy(e.attrs)) for e in graph.edges
    ]
    finding_before = copy.deepcopy(correlation.findings[0].to_dict())

    exposure_overlay(graph, reachability, correlation, _OfflineClient())

    nodes_after = {n.id: (n.kind, n.name, n.attrs) for n in graph.nodes}
    edges_after = [(e.src, e.dst, e.kind, e.attrs) for e in graph.edges]

    assert nodes_after == nodes_before
    assert edges_after == edges_before
    # The finding is untouched (reachable/confirmed/tainted/verdict et al.).
    assert correlation.findings[0].to_dict() == finding_before


# -- endpoint routing (503 while warming / 200 when ready) --------------------


def _scan(status: str, exposure: dict[str, Any] | None = None, note: str | None = None):
    from scanner.web.app import _ScanState

    state = _ScanState(repo="acme-api")
    if status == "ready":
        state.set_ready(findings_total=0, exploitable=0, findings=[])
    if exposure is not None:
        state.set_exposure(exposure, note=note)
    return state


def test_endpoint_503_before_scan_ready():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    app_mod.app.state.scan = _scan("scanning")
    with pytest.raises(HTTPException) as exc:
        app_mod.enrichment()
    assert exc.value.status_code == 503
    assert exc.value.detail == "scan not ready"


def test_endpoint_503_while_overlay_still_warming():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    # Scan is ready but the overlay has not been cached yet.
    app_mod.app.state.scan = _scan("ready")
    with pytest.raises(HTTPException) as exc:
        app_mod.enrichment()
    assert exc.value.status_code == 503


def test_endpoint_200_when_overlay_ready():
    from scanner.web import app as app_mod

    overlay = {EP_PUBLIC: {"label": "POST /documents/import", "value": "internet-facing"}}
    app_mod.app.state.scan = _scan("ready", exposure=overlay)
    out = app_mod.enrichment()
    assert out["repo"] == "acme-api"
    assert out["exposure"] == overlay
    assert "note" not in out


def test_endpoint_200_with_note_on_degraded_overlay():
    from scanner.web import app as app_mod

    app_mod.app.state.scan = _scan(
        "ready", exposure={}, note="exposure overlay unavailable: RuntimeError: boom"
    )
    out = app_mod.enrichment()
    assert out["exposure"] == {}
    assert out["note"].startswith("exposure overlay unavailable")


# -- per-repo routing (?repo= selects a warmed scan by repo_path basename) -----


def _scan_for_repo(
    repo_path: str,
    status: str,
    exposure: dict[str, Any] | None = None,
    inferred_edges: list[dict[str, Any]] | None = None,
    likely_reachable: list[dict[str, Any]] | None = None,
):
    from scanner.web.app import _ScanState, _repo_name

    state = _ScanState(repo=_repo_name(repo_path), repo_path=repo_path)
    if status == "ready":
        state.set_ready(findings_total=0, exploitable=0, findings=[])
    if exposure is not None:
        state.set_exposure(
            exposure,
            inferred_edges=inferred_edges,
            likely_reachable=likely_reachable,
        )
    return state


def test_endpoint_no_param_returns_primary_unchanged():
    # With multiple warmed scans, no ``repo`` param still serves the primary
    # (app.state.scan == the first scan) exactly as before.
    from scanner.web import app as app_mod

    primary_overlay = {EP_PUBLIC: {"label": "primary", "value": "internet-facing"}}
    secondary_overlay = {EP_PUBLIC: {"label": "secondary", "value": "internal"}}
    primary = _scan_for_repo(
        "/app/samples/acme-api", "ready", exposure=primary_overlay
    )
    secondary = _scan_for_repo(
        "/app/samples/plugin-reports", "ready", exposure=secondary_overlay
    )
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary, secondary]

    out = app_mod.enrichment()
    assert out["repo"] == "acme-api"
    assert out["exposure"] == primary_overlay


def test_endpoint_repo_param_selects_secondary_scan():
    # ``?repo=plugin-reports`` returns the SECONDARY scan's own overlays,
    # matched by the basename of its repo_path.
    from scanner.web import app as app_mod

    primary_overlay = {EP_PUBLIC: {"label": "primary", "value": "internet-facing"}}
    secondary_overlay = {EP_PUBLIC: {"label": "secondary", "value": "internal"}}
    primary = _scan_for_repo(
        "/app/samples/acme-api", "ready", exposure=primary_overlay
    )
    secondary = _scan_for_repo(
        "/app/samples/plugin-reports",
        "ready",
        exposure=secondary_overlay,
        inferred_edges=[{"from": "n:a", "to": "n:b"}],
        likely_reachable=[{"dependency_id": DEP_YAML}],
    )
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary, secondary]

    out = app_mod.enrichment(repo="plugin-reports")
    assert out["repo"] == "plugin-reports"
    assert out["exposure"] == secondary_overlay
    assert out["inferred_edges"] == [{"from": "n:a", "to": "n:b"}]
    assert out["likely_reachable"] == [{"dependency_id": DEP_YAML}]


def test_endpoint_unknown_repo_404():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    primary = _scan_for_repo("/app/samples/acme-api", "ready", exposure={})
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary]
    with pytest.raises(HTTPException) as exc:
        app_mod.enrichment(repo="does-not-exist")
    assert exc.value.status_code == 404
    assert exc.value.detail == "unknown repo"


def test_endpoint_repo_matched_but_overlay_not_ready_503():
    # The repo matches by basename, but its enrichment has not been cached yet.
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    primary = _scan_for_repo("/app/samples/acme-api", "ready", exposure={})
    secondary = _scan_for_repo("/app/samples/plugin-reports", "ready")
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary, secondary]
    with pytest.raises(HTTPException) as exc:
        app_mod.enrichment(repo="plugin-reports")
    assert exc.value.status_code == 503
    assert exc.value.detail == "scan not ready"
