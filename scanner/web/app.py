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
from scanner.mcp import state
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


def _run_warm_scan(scan_state: _ScanState, repo_path: str) -> None:
    """Background worker: warm the scan and record ready/degraded. Never raises."""
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
