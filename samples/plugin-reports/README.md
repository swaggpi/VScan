# Plugin Reports API

A reporting service with a pluggable, reflectively-dispatched rendering and
parsing engine. The libraries that handle untrusted input are selected at
runtime (`getattr` / a loader registry), so their call sites are resolved
dynamically rather than named in the source.

## Public endpoints

These are exposed to the internet with no authentication:

- `POST /reports/render` — render a report from a template in the request body.
- `POST /reports/import` — import a report spec (YAML) from the request body.
- `POST /reports/export` — re-serialize an XML report from the request body.
- `GET /reports/search` — search reports by title (`?q=`).
- `GET /reports/attachment` — download a report attachment (`?name=`).
- `POST /reports/rebuild` — rebuild the report cache by running a named task.
- `POST /webhooks/deliver` — deliver a report to a callback URL in the body.
- `GET /healthz` — liveness probe.
