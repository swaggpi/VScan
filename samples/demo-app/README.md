# demo-app

A small, mostly-secure Flask service used to showcase the `vulnreach`
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
