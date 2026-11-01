# Plugin Reports API

A small **public** reporting service that renders report templates on demand.

## Endpoints

- `POST /reports/render` — **public**, no authentication. Accepts a report
  template in the request body and renders it with the configured engine.
- `GET /healthz` — liveness probe.

## Rendering engine

The rendering engine is chosen reflectively at request time (see
`render_service.py`), so the active template library is resolved dynamically
rather than named at the call site.
