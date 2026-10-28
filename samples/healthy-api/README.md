# Scribe Notes API — the healthy / up-to-date contrast fixture

A small, tidy, **well-maintained** FastAPI service used by the VScan dashboard as
the deliberate counterpoint to [`samples/acme-api`](../acme-api). Where ACME pins
old, vulnerable dependency versions to light up the impact funnel, Scribe does
the opposite: every dependency is pinned to a **current release with no known OSV
advisory**, so an audit comes back essentially clean.

This is the "N dependencies, 0 known CVEs, nothing reachable to worry about"
story — what a healthy project looks like in the viewer.

## What it is

A minimal notes service: create, read, update, delete, search, and share notes.
It is genuinely layered so the reachability graph has real shape, not so it hides
anything.

```
app.py                       FastAPI app; includes the routers (entry points)
api/notes.py                 7 note routes (CRUD + search + share)
api/health.py                1 ops route (health/version)
services/note_service.py     business logic the routes delegate into
services/link_service.py     the single outbound-HTTP path (httpx)
core/config.py               env-driven config (stdlib only)
core/store.py                in-memory note store (stdlib only)
core/serializer.py           JSON serialization (orjson)
core/logging.py              structured logging (structlog)
```

Call chains run **route → handler → service → core → dependency**, e.g.:

```
POST /notes
  → api.notes.create_note        (handler)
  → note_service.create_note     (service)
  → store.insert                 (core)
  → serializer.to_jsonable       (core → orjson)
```

## Routes (8 entry points)

| Method | Path                   | Reaches |
| ------ | ---------------------- | ------- |
| GET    | `/notes`               | store, orjson |
| POST   | `/notes`               | store, orjson, python-dateutil |
| GET    | `/notes/search`        | store, orjson |
| GET    | `/notes/{note_id}`     | store, orjson |
| PUT    | `/notes/{note_id}`     | store, orjson, python-dateutil |
| DELETE | `/notes/{note_id}`     | store |
| POST   | `/notes/{note_id}/share` | httpx, orjson |
| GET    | `/health`              | config |

## Dependencies — all current, all clean

All pins are verified clean against OSV via `vscan audit`. The reachable set
(fastapi, httpx, orjson, python-dateutil) carries **0 known CVEs**.

See [`requirements.txt`](./requirements.txt) for the exact pins. Note that
`starlette` and `orjson` were pinned forward to the first advisory-free releases
(`starlette==1.3.1`, `orjson==3.11.6`) — the versions one tends to reach for
first both had advisories, which is exactly the swap a well-maintained project
makes.

## Reproduce

```bash
# Clean funnel: 8 deps · 0 known CVEs · 0 reachable · 0 exploitable
vscan audit samples/healthy-api

# Regenerate the dashboard bundle (the "Healthy API" switcher segment)
vscan audit samples/healthy-api --bundle dashboard/healthy-bundle.json
```
