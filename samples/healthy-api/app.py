"""Scribe Notes API -- a small, tidy, well-maintained note-taking service.

This is the HEALTHY contrast fixture for the ``VScan`` reachability engine. Where
``samples/acme-api`` deliberately pins old, vulnerable dependency versions to
light up the impact funnel, this app does the opposite: it is a realistic,
modern FastAPI service whose dependencies are all pinned to CURRENT releases
with no known advisories. Scanned, it tells the boring-in-a-good-way story every
team wants -- "N dependencies, 0 known CVEs, nothing reachable to worry about".

The structure is still genuinely layered, so the call graph has real shape:

    app.py                  registers the API routers (entry points)
      -> api/notes.py       the note CRUD + share + search routes
      -> api/health.py      the operational health/version route
         -> services/       business logic the routes delegate into
            -> core/        shared infrastructure (store, config, logging,
                            JSON serialization, outbound HTTP)
               -> deps      orjson / python-dateutil / httpx / structlog

Every route is a plain, decorated handler so the engine can resolve the
route -> handler edge and follow the chain down through ``services/`` and
``core/`` to the (clean) dependency it ultimately calls.
"""

from fastapi import FastAPI

from api import health, notes
from core.logging import configure_logging

configure_logging()

app = FastAPI(
    title="Scribe Notes API",
    version="1.4.0",
    summary="A small, well-maintained notes service.",
)
app.include_router(notes.router)
app.include_router(health.router)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080)
