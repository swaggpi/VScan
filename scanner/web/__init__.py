"""FastAPI backend exposing the vscan scanner as a small web service.

The service (:mod:`scanner.web.app`) warms a REAL vscan scan of a bundled demo
repository on startup, caches it in process (via the same accessors the MCP
server uses, :mod:`scanner.mcp.state`), and serves the headline scan stats over
HTTP. Run it with the ``vscan-web`` console script or ``python -m scanner.web``.

``fastapi`` / ``uvicorn`` are web-only dependencies; the FastAPI ``app`` lives
in :mod:`scanner.web.app` and is imported lazily so the core package stays
importable without them.
"""

from __future__ import annotations

__all__ = ["app"]


def __getattr__(name: str):  # pragma: no cover - thin lazy-import shim
    """Expose ``scanner.web.app`` lazily so core stays web-dep-free."""
    if name == "app":
        from .app import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
