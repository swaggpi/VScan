# Acme DocVault API (demo fixture)

A realistic, layered Flask service used as the **default demo** for the VScan
dashboard. It is a defensive-security fixture: there is no exploit code here, and
the only thing "vulnerable" about it is that several dependency *versions* in
`requirements.txt` are intentionally pinned to old releases with known
advisories. The point of the fixture is to show a reachability **funnel** that
reads like a genuine, substantial problem:

```
19 dependencies  →  145 known CVEs  →  16 reachable  →  4 vulnerable-function confirmed  →  1 exploitable
```

Single language (Python only), ~120 graph nodes, so the dashboard renders the
full graph.

## Architecture (where the depth and breadth come from)

```
app.py                      Flask app; registers 5 blueprints
api/                        HTTP layer -- one blueprint per feature area
  documents.py   reports.py   auth.py   webhooks.py   admin.py
services/                   business logic; routes call these
  document_service.py  report_service.py  auth_service.py
  webhook_service.py   admin_service.py
core/                       shared infra; services call these (the sinks live here)
  config_loader.py   http_client.py   templating.py   db.py   serializer.py
maintenance/                cron/operator jobs -- NOT wired to any route
  sync.py (urllib3)   deploy.py (paramiko)
cli/                        developer CLIs -- NOT wired to any route
  thumbnails.py (Pillow)   export_xml.py (lxml)   signing.py (cryptography)
```

11 public routes across 5 blueprints. The flagship call chain is **five function
hops** deep between the route and the dependency it calls.

## Ground-truth findings

### Exploitable (tainted) — the flagship

`POST /documents/import` reads the raw request body and threads it, unchanged,
through every hop as a plain function argument until it reaches an unsafe PyYAML
deserialization sink:

```
POST /documents/import
  request.get_data()                                   # SOURCE (attacker input)
  → api/documents.py        import_document(payload)
  → services/document_service.py  ingest(payload)
  → services/document_service.py  build_spec(payload)
  → core/config_loader.py   load_spec(text)
  → core/config_loader.py   parse_yaml(text)
  → yaml.full_load(text)                               # SINK (PyYAML 5.3.1)
```

* **Dependency:** PyYAML 5.3.1 — **CVE-2020-14343** (arbitrary code execution via
  `yaml.full_load`/`FullLoader` on the `python/object/new` constructor).
* **Verdict:** reachable + symbol-confirmed + **tainted**. `yaml.full_load` is
  the exact function CVE-2020-14343 names, and the taint pass proves the request
  body reaches it. This is the one finding that is genuinely exploitable.

PyYAML is *also* reachable from `GET /admin/config`, but that path parses a
fixed, bundled default-config constant — not request data — so it carries **no**
taint. A sink can be reached many ways and still be exploitable from only one.

### Reachable but NOT exploitable (the deliberate contrast)

* **Jinja2 2.10** — reachable from `GET /reports/<report_id>`
  (`render_report → report_service.render → templating.render_page →
  jinja2.escape`). CVE-2019-10906 / CVE-2020-28493. Only the path id and
  server-side content reach the sink; a URL path parameter is **not** a taint
  source, so the flow is not tainted.
* **requests 2.19.1** — reachable from `POST /webhooks/dispatch`
  (`dispatch_webhook → webhook_service.notify → http_client.post_status →
  requests.post`). CVE-2018-18074. The handler reads the request body but
  forwards only a fixed status string to a pinned internal URL, so attacker
  input never reaches the HTTP sink.
* **Flask 0.12.2** — reachable from every route (it is the `request` source
  library). CVE-2018-1000656. It receives attacker data; it is not a sink that
  attacker data flows *into*, so it is not an "exploitable" finding.

### Vulnerable but UNREACHABLE from the web service

These old, vulnerable pins are reached only from offline CLI/cron code, so no
public route can reach them:

| Dependency       | Pin          | Used only by                 |
|------------------|--------------|------------------------------|
| urllib3          | 1.24.1       | `maintenance/sync.py` (cron) |
| paramiko         | 2.4.1        | `maintenance/deploy.py`      |
| Pillow           | 7.1.0        | `cli/thumbnails.py`          |
| lxml             | 4.5.0        | `cli/export_xml.py`          |
| cryptography     | 2.8          | `cli/signing.py`             |

Note: Pillow carries the one KEV (actively-exploited) finding and the highest
EPSS scores, yet it is **unreachable** — a good illustration that raw severity
without reachability over-counts risk.

### Declared but never imported

`Werkzeug`, `certifi`, `idna`, `rsa`, `Pygments`, `gunicorn`, `MarkupSafe`,
`itsdangerous`, `click`, `python-dateutil` are declared in `requirements.txt`
but never imported in code. Some are vulnerable (e.g. Werkzeug 0.14.1,
Pygments 2.3.0); none are reachable.

## Running it

```
vscan audit samples/acme-api                                   # networked (OSV)
vscan audit samples/acme-api --bundle dashboard/demo-bundle.json
```

The taint and reachability verdicts are deterministic and need no network; only
the CVE counts require OSV.
