# demo-app

A small, mostly-secure Flask service used to showcase the `VScan`
reachability engine. This is a **defensive-security demo fixture**: there is no
exploit code anywhere in it. The only thing "vulnerable" about the app is that a
few dependency *versions* in `requirements.txt` are intentionally outdated.

The point of the fixture is to show the difference between *having* an outdated
dependency and *being able to reach it* from a public HTTP route.

## What the service does

A notes/config/report API with three public HTTP routes:

| Method & path            | Handler                                  | What it reaches                        |
|--------------------------|------------------------------------------|----------------------------------------|
| `POST /configs/import`   | `controllers.config_controller.import_config` | PyYAML (parses an uploaded YAML config) |
| `GET  /reports/<id>`     | `controllers.report_controller.get_report`    | Jinja2 (renders a report to HTML)       |
| `GET  /health`           | `controllers.health_controller.health`        | requests (checks an upstream service)   |

All three routes are **public** (registered as blueprints on the app in
`app.py`); there is no auth layer in this demo.

## Architecture

The code is layered so that the call chains are genuinely multi-file and
several hops deep:

```
app.py                      Flask app; registers the blueprints below
controllers/                HTTP blueprints (the public entry points)
  config_controller.py        POST /configs/import
  report_controller.py        GET  /reports/<id>
  health_controller.py        GET  /health
services/                   business logic
  config_service.py           ingest -> validation_service
  validation_service.py       validate -> yaml_parser
  report_service.py           build_report -> content_service
  content_service.py          assemble -> template_service
  template_service.py         render -> html_renderer
  health_service.py           check_upstream -> requests.get
parsers/                    request-body parsing
  yaml_parser.py              parse -> loader
  loader.py                   load_document -> yaml.load   (PyYAML)
renderers/
  html_renderer.py            render_html -> jinja2.escape (Jinja2)
maintenance/                offline jobs (NOT wired to any route)
  sync.py                     run_sync (cron/CLI only)
  http.py                     fetch -> urllib3            (urllib3)
tools/                      developer CLI scripts (NOT wired to any route)
  thumbnail_cli.py            make_thumbnail -> PIL.Image  (Pillow)
```

Every function in a route's reachable call chain is a plain module-level
function reached through a plain import, so the analyzer can resolve the chain
end to end.

## Reachability story

* **PyYAML** and **Jinja2** are outdated and carry advisories, and they are each
  reachable from a public route through a deep (five-function-hop) chain. These
  are the findings that matter.
* **requests** and **Flask** are current (patched) and carry no advisory. They
  *are* reachable, but produce no finding — a reachable-but-safe dependency.
* **urllib3** and **Pillow** are outdated and carry advisories, but they are
  only used by the offline `maintenance/` sync job and the `tools/` CLI script
  respectively. No public route reaches them, so they are reported as *not
  reachable from a public entry point*.

## Data and storage

Configuration records and rendered reports are persisted in **PostgreSQL** and
accessed through **SQLAlchemy**: `POST /configs/import` writes the parsed
document as a config record, and `GET /reports/<report_id>` loads a report row
by its id before rendering it. (In this fixture the persistence layer is stubbed
out — `assemble` returns placeholder content — so the scan stays offline and
deterministic; the schema above is the shape the service is modelled on.)

A small **Redis** cache fronts report rendering so repeat `GET /reports/<id>`
requests avoid re-rendering, and `GET /health` performs a live check against an
**upstream status service** (`https://status.internal.example/health`) over HTTP
using the `requests` client — that upstream call is what makes `check_upstream`
reach the `requests` dependency.

## Auth model

**All routes are public and unauthenticated.** There is no login, session, API
key or token layer anywhere in the app; the three blueprints are registered
directly on the Flask app in `app.py` and any client can call them. This is
deliberate for the fixture — it keeps every public entry point trivially
reachable so the reachability story is about the *call chain*, not about access
control.

## Data handling

`POST /configs/import` accepts **user-supplied YAML** in the request body: the
raw bytes flow through `ingest` → `validate` → `parse` → `load_document`, where
PyYAML's `yaml.load` turns them into Python objects. Because the input is
untrusted and the pinned PyYAML version is outdated, this is the chain the
reachability engine flags. `GET /reports/<report_id>` likewise takes a
caller-controlled `report_id` and renders it into HTML, escaping the untrusted
fields through Jinja2 in `render_html` before they reach the page.
