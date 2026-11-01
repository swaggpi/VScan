"""The vscan web service: real scans on startup, health + grounded explain.

On startup the app warms one or more REAL vscan scans of the bundled demo
repo(s) and caches each. ``GET /api/health`` reports the primary scan's real
stats; ``POST /api/explain`` returns a live, grounded attack-narrative plus
remediation for one finding (see :mod:`scanner.web.explain`); ``POST /api/chat``
is a free-form advisory chat where the model answers by calling vscan's
read-only MCP tools over the warmed primary scan (see :mod:`scanner.web.chat`).

The set of demo repos comes from ``VSCAN_DEMO_REPOS`` (comma-separated) and
defaults to the single ``VSCAN_DEMO_REPO`` (default ``/app/samples/acme-api`` --
the in-container path). Each repo is warmed on its own background thread, and
``/api/explain`` searches across every warmed scan, so extra demo scans can be
added later with zero code change.

The scans reuse the MCP server's cached accessors verbatim
(:mod:`scanner.mcp.state`) -- no scanning logic is reimplemented here. The
ranked audit (:func:`scanner.correlate.report.audit`) gives both the headline
summary counts and the full findings list; both are cached per scan. This
mirrors the ``offline=False`` default of the ``vscan_audit`` MCP tool so the
deploy box's network is used for OSV/KEV/EPSS correlation.

Nothing here touches reachability/taint/verdict logic: the service is a pure
*reader* of scan output. Each warm scan runs on a background thread so a slow
first correlation never blocks startup indefinitely; until it finishes health
honestly reports ``"scanning"``, and any failure degrades gracefully to
``"degraded"`` with the error string rather than crashing the server.
"""

from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from scanner.agent import LLMClient
from scanner.correlate import report
from scanner.enrich import exposure_overlay, infer_edges, likely_reachability
from scanner.mcp import state
from scanner.pentest import attack_surface as compute_attack_surface
from scanner.taint import compute_taint
from scanner.web import chat as chat_mod
from scanner.web import explain as explain_mod

# In-container default; overridable via env for local runs (see VSCAN_DEMO_REPO).
_DEFAULT_DEMO_REPO = "/app/samples/acme-api"


@dataclass
class _ScanState:
    """Thread-safe holder for one warm-scan's result.

    ``status`` moves ``"scanning"`` -> ``"ready"`` on success, or
    ``"scanning"`` -> ``"degraded"`` on failure (with ``error`` set). The two
    headline counts come from the real audit summary and the full ``findings``
    list is the ranked audit's findings (what ``/api/explain`` looks up by
    ``(dependency_id, vuln_id)``); both stay empty/``0`` until the scan is ready.
    Every read/write goes through :attr:`lock`.
    """

    repo: str
    repo_path: str = ""
    status: str = "scanning"
    findings_total: int = 0
    exploitable: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    # Advisory, additive Phase-1 EXPOSURE overlay (see scanner.enrich.exposure):
    # per public entry point, whether the docs place it internet-facing vs.
    # internal and whether it is auth-gated. Warmed on a background thread AFTER
    # the scan is ready so health/explain/chat go live immediately; ``None``
    # until ready. ``exposure_note`` carries a degrade reason if it could not be
    # built (the overlay then stays ``{}`` rather than failing the endpoint).
    exposure: dict[str, Any] | None = None
    exposure_note: str | None = None
    # Advisory, additive Phase-2 INFERRED-EDGE tier (see scanner.enrich.edges):
    # grounded inferred ``calls`` edges filling unresolved call sites, plus the
    # "likely-reachable" dependencies they would surface on a throwaway augmented
    # COPY of the graph. Warmed in the SAME background step as the exposure
    # overlay, from the cached deterministic graph/reachability/correlation. They
    # NEVER enter the graph findings/taint/verdicts read; ``None`` until warmed.
    inferred_edges: list[dict[str, Any]] | None = None
    likely_reachable: list[dict[str, Any]] | None = None
    # Advisory, additive Tier-A ATTACK-SURFACE analysis (see scanner.pentest):
    # per public entry point, AI-hypothesis code-level vulnerabilities in the
    # app's OWN reachable code. Warmed in the SAME background step as the other
    # overlays, from the cached graph/reachability + the repo source on disk.
    # Every finding is advisory/``ai-hypothesis`` and NEVER mutates or influences
    # the graph/reachability/taint/findings; ``None`` until warmed.
    attack_surface: dict[str, Any] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable copy of the headline state under the lock.

        The full ``findings`` list is intentionally excluded -- health reports
        only counts; explain reads findings via :meth:`findings_snapshot`.
        """
        with self.lock:
            return {
                "status": self.status,
                "repo": self.repo,
                "findings_total": self.findings_total,
                "exploitable": self.exploitable,
                "error": self.error,
            }

    def set_ready(
        self, *, findings_total: int, exploitable: int, findings: list[dict[str, Any]]
    ) -> None:
        """Record a successful scan's counts + findings and flip to ``"ready"``."""
        with self.lock:
            self.status = "ready"
            self.findings_total = findings_total
            self.exploitable = exploitable
            self.findings = findings
            self.error = None

    def set_degraded(self, error: str) -> None:
        """Record a failed scan: ``"degraded"`` with the error string, no crash."""
        with self.lock:
            self.status = "degraded"
            self.error = error

    def current_status(self) -> str:
        """Return the current ``status`` string under the lock."""
        with self.lock:
            return self.status

    def findings_snapshot(self) -> list[dict[str, Any]]:
        """Return a shallow copy of the cached findings list under the lock."""
        with self.lock:
            return list(self.findings)

    def set_exposure(
        self,
        exposure: dict[str, Any],
        *,
        note: str | None = None,
        inferred_edges: list[dict[str, Any]] | None = None,
        likely_reachable: list[dict[str, Any]] | None = None,
    ) -> None:
        """Cache the advisory enrichment overlays (and an optional degrade note).

        The exposure overlay and the Phase-2 inferred-edge / likely-reachability
        lists are cached together under one lock so the ``/api/enrichment``
        endpoint never sees a half-warmed state.
        """
        with self.lock:
            self.exposure = exposure
            self.exposure_note = note
            self.inferred_edges = inferred_edges
            self.likely_reachable = likely_reachable

    def exposure_snapshot(self) -> tuple[dict[str, Any] | None, str | None]:
        """Return ``(exposure_copy_or_None, note)`` under the lock.

        ``None`` means the overlay is not warmed yet (still scanning or still
        computing); a dict (possibly ``{}`` with a note) means it is ready.
        """
        with self.lock:
            exposure = dict(self.exposure) if self.exposure is not None else None
            return exposure, self.exposure_note

    def enrichment_lists_snapshot(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return ``(inferred_edges, likely_reachable)`` copies under the lock.

        Each defaults to ``[]`` when not warmed, so the endpoint always carries
        both Phase-2 keys even if only the exposure overlay was cached.
        """
        with self.lock:
            inferred = list(self.inferred_edges) if self.inferred_edges else []
            likely = list(self.likely_reachable) if self.likely_reachable else []
            return inferred, likely

    def set_attack_surface(self, attack_surface: dict[str, Any]) -> None:
        """Cache the advisory Tier-A attack-surface analysis under the lock."""
        with self.lock:
            self.attack_surface = attack_surface

    def attack_surface_snapshot(self) -> dict[str, Any] | None:
        """Return a copy of the attack-surface analysis, or ``None`` if unwarmed.

        ``None`` means it is not warmed yet (still scanning or still computing);
        a dict (possibly with empty findings + a ``note``) means it is ready.
        """
        with self.lock:
            if self.attack_surface is None:
                return None
            return dict(self.attack_surface)


def _demo_repo_path() -> str:
    """The demo repo to scan: env ``VSCAN_DEMO_REPO`` or the in-container default."""
    return os.environ.get("VSCAN_DEMO_REPO", _DEFAULT_DEMO_REPO)


def _demo_repo_paths() -> list[str]:
    """The demo repos to warm: ``VSCAN_DEMO_REPOS`` (comma-separated), else one.

    When ``VSCAN_DEMO_REPOS`` is set to a non-empty comma-separated list it wins;
    otherwise we fall back to the single :func:`_demo_repo_path` (which keeps
    ``VSCAN_DEMO_REPO`` / the acme-api default as the sole repo). This lets more
    demo scans be added later purely via env, with no code change.
    """
    raw = os.environ.get("VSCAN_DEMO_REPOS")
    if raw:
        repos = [part.strip() for part in raw.split(",") if part.strip()]
        if repos:
            return repos
    return [_demo_repo_path()]


def _repo_name(repo_path: str) -> str:
    """A short display name for a repo path (its final path component)."""
    return os.path.basename(os.path.normpath(repo_path)) or repo_path


def _warm_scan(repo_path: str) -> dict[str, Any]:
    """Run the REAL vscan scan for ``repo_path`` and return counts + findings.

    Reuses the MCP state accessors so the graph/reachability/correlation are
    built (and cached) exactly as the ``vscan_audit`` tool builds them, with
    ``offline=False`` so OSV/KEV/EPSS correlation uses the network. The derived
    taint signal is computed the same way the finding-detail path does, then fed
    into the ranked audit so the summary carries the exploitable count. We read
    from the audit payload and change nothing about the scan itself:

    * ``findings_total`` <- ``summary.total_vulnerabilities`` (every finding)
    * ``exploitable``    <- ``summary.taint_confirmed_vulnerabilities`` (findings
      whose derived taint verdict is ``"tainted"`` -- a proven source->sink flow)
    * ``findings``       <- the full ranked ``findings`` list, cached verbatim so
      ``/api/explain`` can look a finding up by ``(dependency_id, vuln_id)``.
    """
    abspath = state.resolve_repo(repo_path)
    graph, corr = state.get_correlation(repo_path, offline=False)
    _, reach = state.get_reachability(repo_path)
    taint_map = compute_taint(graph, reach, abspath)
    payload = report.audit(graph, corr, reach, taint=taint_map)
    summary = payload["summary"]
    return {
        "findings_total": int(summary["total_vulnerabilities"]),
        "exploitable": int(summary["taint_confirmed_vulnerabilities"]),
        "findings": list(payload["findings"]),
    }


def _warm_exposure_overlay(repo_path: str) -> dict[str, Any]:
    """Build the advisory per-entry-point EXPOSURE overlay for a warm repo.

    Reuses the same cached graph/reachability/correlation accessors the warm
    scan populated (no re-scan, no extra network), then promotes the agent
    layer's advisory exposure judgement into an entry-point-keyed overlay (see
    :func:`scanner.enrich.exposure.exposure_overlay`). Read-only and additive:
    it never changes a finding's reachable/confirmed/tainted state or the graph.
    The model is used iff ``LLM_*`` is configured; otherwise the overlay falls
    back to the deterministic offline heuristic and still returns grounded data.
    """
    graph, corr = state.get_correlation(repo_path, offline=False)
    _, reach = state.get_reachability(repo_path)
    return exposure_overlay(graph, reach, corr, LLMClient())


def _warm_inferred_edges(
    repo_path: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build the advisory Phase-2 inferred-edge overlay + likely reachability.

    Reuses the SAME cached graph/reachability/correlation the warm scan
    populated (no re-scan, no extra network): the model (when ``LLM_*`` is
    configured) maps unresolved call sites to grounded candidate node ids, and
    :func:`scanner.enrich.likely_reachability` diffs an AUGMENTED COPY of the
    graph against the proven reachability. Read-only and additive -- the inferred
    edges never enter the cached graph that findings/taint/verdicts read, so the
    canonical pipeline's output is byte-identical whether or not this ran.
    Returns ``(inferred_edges, likely_reachable)``.
    """
    graph, corr = state.get_correlation(repo_path, offline=False)
    _, reach = state.get_reachability(repo_path)
    inferred = infer_edges(graph, reach, corr, LLMClient())
    likely = likely_reachability(graph, inferred, reach)
    return inferred, likely["likely_reachable"]


def _warm_attack_surface(
    repo_path: str, exposure: dict[str, Any] | None
) -> dict[str, Any]:
    """Build the advisory Tier-A attack-surface analysis for a warm repo.

    Reuses the SAME cached graph/reachability the warm scan populated (no
    re-scan), reads the repo source from its resolved on-disk path, and runs the
    model (when ``LLM_*`` is configured) over the code reachable from each entry
    point (see :func:`scanner.pentest.attack_surface`). The ``exposure`` overlay
    already built this step is passed through only to tag/prioritise entry
    points. Read-only and additive: every finding is an advisory
    ``ai-hypothesis`` and never changes a finding/verdict or the graph.
    """
    abspath = state.resolve_repo(repo_path)
    graph, _ = state.get_correlation(repo_path, offline=False)
    _, reach = state.get_reachability(repo_path)
    return compute_attack_surface(
        graph, reach, abspath, LLMClient(), exposure=exposure
    )


def _run_warm_scan(scan_state: _ScanState, repo_path: str) -> None:
    """Background worker: warm the scan and record ready/degraded. Never raises.

    Once the scan is ready (so health/explain/chat are live immediately), the
    SAME background thread goes on to warm the advisory enrichment overlays --
    the exposure overlay, the Phase-2 inferred-edge overlay + likely
    reachability, AND the Tier-A attack-surface analysis -- and cache them on the
    scan state. Every overlay is additive and never affects the scan result; any
    failure degrades to empty overlays with a note rather than crashing the
    thread or the server.
    """
    try:
        result = _warm_scan(repo_path)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully, never crash startup
        scan_state.set_degraded(f"{type(exc).__name__}: {exc}")
        return
    scan_state.set_ready(
        findings_total=result["findings_total"],
        exploitable=result["exploitable"],
        findings=result["findings"],
    )
    exposure: dict[str, Any] = {}
    try:
        exposure = _warm_exposure_overlay(repo_path)
        inferred, likely = _warm_inferred_edges(repo_path)
        scan_state.set_exposure(
            exposure, inferred_edges=inferred, likely_reachable=likely
        )
    except Exception as exc:  # noqa: BLE001 - advisory overlays degrade, never crash
        exposure = {}
        scan_state.set_exposure(
            {},
            note=f"enrichment overlay unavailable: {type(exc).__name__}: {exc}",
            inferred_edges=[],
            likely_reachable=[],
        )
    # Tier-A attack surface: advisory AI hypotheses over reachable source. It
    # already degrades internally to empty findings + a note; the guard here
    # only catches an unexpected error gathering the cached graph/source, so the
    # endpoint never hangs at 503 forever.
    try:
        surface = _warm_attack_surface(repo_path, exposure)
    except Exception as exc:  # noqa: BLE001 - advisory analysis degrades, never crash
        surface = {
            "repo": _repo_name(repo_path),
            "entrypoints": {},
            "summary": {
                "total_findings": 0,
                "by_severity": {},
                "entrypoints_with_findings": 0,
            },
            "note": f"attack-surface analysis unavailable: {type(exc).__name__}: {exc}",
        }
    scan_state.set_attack_surface(surface)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Kick off one warm scan per demo repo on daemon threads; never block startup.

    ``app.state.scans`` holds every scan (what ``/api/explain`` searches);
    ``app.state.scan`` aliases the first one so ``/api/health`` keeps reporting
    the primary repo exactly as before.
    """
    repo_paths = _demo_repo_paths()
    scans = [
        _ScanState(repo=_repo_name(path), repo_path=path) for path in repo_paths
    ]
    app.state.scans = scans
    app.state.scan = scans[0]
    for scan_state, repo_path in zip(scans, repo_paths):
        worker = threading.Thread(
            target=_run_warm_scan,
            args=(scan_state, repo_path),
            name=f"vscan-warm-scan:{scan_state.repo}",
            daemon=True,
        )
        worker.start()
    yield


app = FastAPI(
    title="vscan web",
    summary="Reachability-aware dependency vulnerability scanner, over HTTP.",
    lifespan=_lifespan,
)


@app.get("/api/health")
def health() -> dict[str, Any]:
    """Report the warm scan's real status and headline counts.

    ``status`` is ``"scanning"`` while the startup scan runs, ``"ready"`` once it
    succeeds (with real ``findings_total`` / ``exploitable`` counts), or
    ``"degraded"`` with ``error`` set if the scan failed -- the server stays up
    either way.
    """
    scan_state: _ScanState = app.state.scan
    return scan_state.snapshot()


# The exposed read-only MCP tool registry (schemas + dispatch), built once and
# reused across requests so the warm scan's caches are hit, not re-scanned. It
# is ``None`` when the optional ``mcp`` dependency is absent -- chat then
# degrades to a tool-less reply rather than failing.
_CHAT_REGISTRY: Any = None
_CHAT_REGISTRY_BUILT = False


def _chat_registry() -> Any:
    """Lazily build and cache the chat tool registry (see :data:`_CHAT_REGISTRY`)."""
    global _CHAT_REGISTRY, _CHAT_REGISTRY_BUILT
    if not _CHAT_REGISTRY_BUILT:
        _CHAT_REGISTRY = chat_mod.build_registry()
        _CHAT_REGISTRY_BUILT = True
    return _CHAT_REGISTRY


class ChatMessage(BaseModel):
    """One turn in the chat transcript."""

    role: str
    content: str


class ChatRequest(BaseModel):
    """Request body for ``POST /api/chat``: the running conversation."""

    messages: list[ChatMessage]


@app.post("/api/chat")
def chat(req: ChatRequest) -> dict[str, Any]:
    """Free-form advisory chat: the model answers by calling vscan's read-only
    MCP tools over the warmed primary scan.

    Returns 200 ``{"reply", "tool_calls", "model"}`` where ``tool_calls`` is the
    "tools used" trace (``{name, arguments, ok, summary}`` per executed tool).
    503 ``"scan not ready"`` while the primary scan is still warming (or
    degraded): there is nothing to ground the chat on yet. Otherwise the loop
    runs via :func:`scanner.web.chat.run_chat`, which never raises -- an
    unavailable model or any mid-loop failure degrades to a graceful 200 reply.
    """
    scan_state: _ScanState | None = getattr(app.state, "scan", None)
    if scan_state is None or scan_state.current_status() != "ready":
        raise HTTPException(status_code=503, detail="scan not ready")

    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    return chat_mod.run_chat(
        messages,
        LLMClient(),
        repo_path=scan_state.repo_path,
        registry=_chat_registry(),
    )


class ExplainRequest(BaseModel):
    """Request body for ``POST /api/explain``: identifies one finding."""

    dependency_id: str
    vuln_id: str


@app.post("/api/explain")
def explain(req: ExplainRequest) -> dict[str, Any]:
    """Return a live, grounded attack-narrative + remediation for one finding.

    Looks the finding up by ``(dependency_id, vuln_id)`` across every warmed
    scan and hands it to :func:`scanner.web.explain.explain_finding`, which
    phrases the finding's own facts via the configured model (provenance
    ``"llm"``) or a deterministic grounded template (``"offline-heuristic"``).
    Never raises to the client:

    * 200 with the explanation when a matching finding is found in a ready scan;
    * 503 ``"scan not ready"`` when no match is found yet but a scan is still
      warming (the finding may still appear);
    * 404 ``"finding not in live scan"`` when every scan has finished warming and
      no finding matches.
    """
    scans: list[_ScanState] = getattr(app.state, "scans", [])

    for scan_state in scans:
        if scan_state.current_status() != "ready":
            continue
        finding = explain_mod.find_finding(
            scan_state.findings_snapshot(), req.dependency_id, req.vuln_id
        )
        if finding is not None:
            return explain_mod.explain_finding(finding, LLMClient())

    if any(scan_state.current_status() == "scanning" for scan_state in scans):
        raise HTTPException(status_code=503, detail="scan not ready")
    raise HTTPException(status_code=404, detail="finding not in live scan")


@app.get("/api/enrichment")
def enrichment(repo: str | None = None) -> dict[str, Any]:
    """Return the advisory, additive per-entry-point enrichment for one repo.

    Each warmed scan gets its OWN overlays (see :mod:`scanner.enrich.exposure`
    and :mod:`scanner.enrich.edges`) warmed on its background thread AFTER that
    scan is ready. The optional ``repo`` query param selects which warmed scan
    to report, matched against ``app.state.scans`` by the basename of each
    scan's ``repo_path`` (e.g. ``acme-api``, ``plugin-reports``). With no param
    this reports the PRIMARY scan exactly as before. The endpoint reports:

    * 404 ``"unknown repo"`` when a ``repo`` is given but no warmed scan matches;
    * 503 ``"scan not ready"`` while the selected scan is still warming OR its
      overlays are still being built (there is nothing to serve yet);
    * 200 ``{"repo", "exposure": {<ep_id>: {...}}, "inferred_edges": [...],
      "likely_reachable": [...]}`` once the overlays are ready (with an extra
      ``"note"`` if they degraded to empty overlays on error).

    It is a pure reader of cached state and never 500s: the overlay computation
    already degrades to empty overlays with a note, and nothing here raises. All
    overlays are ADVISORY -- they never change any finding's reachable /
    confirmed / tainted state or verdict; ``likely_reachable`` is a lead, never a
    proven reachability result.
    """
    if repo is None:
        scan_state: _ScanState | None = getattr(app.state, "scan", None)
    else:
        scans: list[_ScanState] = getattr(app.state, "scans", [])
        scan_state = next(
            (s for s in scans if _repo_name(s.repo_path) == repo), None
        )
        if scan_state is None:
            raise HTTPException(status_code=404, detail="unknown repo")
    if scan_state is None:
        raise HTTPException(status_code=503, detail="scan not ready")
    exposure, note = scan_state.exposure_snapshot()
    if exposure is None:
        raise HTTPException(status_code=503, detail="scan not ready")
    inferred_edges, likely_reachable = scan_state.enrichment_lists_snapshot()
    payload: dict[str, Any] = {
        "repo": scan_state.repo,
        "exposure": exposure,
        "inferred_edges": inferred_edges,
        "likely_reachable": likely_reachable,
    }
    if note:
        payload["note"] = note
    return payload


@app.get("/api/attack-surface")
def attack_surface(repo: str | None = None) -> dict[str, Any]:
    """Return the advisory, additive Tier-A attack-surface analysis for one repo.

    Mirrors ``/api/enrichment``: each warmed scan gets its own analysis (see
    :mod:`scanner.pentest`) warmed on its background thread AFTER that scan is
    ready. The optional ``repo`` query param selects which warmed scan to report
    (matched against ``app.state.scans`` by the basename of each scan's
    ``repo_path``); with no param this reports the PRIMARY scan. It reports:

    * 404 ``"unknown repo"`` when a ``repo`` is given but no warmed scan matches;
    * 503 ``"scan not ready"`` while the selected scan is still warming OR its
      analysis has not been cached yet (there is nothing to serve yet);
    * 200 ``{"repo", "entrypoints": {<ep_id>: {label, exposure, findings:[...]}},
      "summary": {...}}`` once ready (with an extra ``"note"`` if the model was
      unavailable or the analysis degraded).

    It is a pure reader of cached state and never 500s. Every finding is an
    UNVERIFIED HYPOTHESIS (``provenance == "ai-hypothesis"``, ``advisory ==
    True``); nothing here changes any finding's reachable/confirmed/tainted
    state or verdict.
    """
    if repo is None:
        scan_state: _ScanState | None = getattr(app.state, "scan", None)
    else:
        scans: list[_ScanState] = getattr(app.state, "scans", [])
        scan_state = next(
            (s for s in scans if _repo_name(s.repo_path) == repo), None
        )
        if scan_state is None:
            raise HTTPException(status_code=404, detail="unknown repo")
    if scan_state is None:
        raise HTTPException(status_code=503, detail="scan not ready")
    surface = scan_state.attack_surface_snapshot()
    if surface is None:
        raise HTTPException(status_code=503, detail="scan not ready")
    return surface
