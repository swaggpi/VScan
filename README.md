# VScan

A reachability-aware dependency vulnerability scanner.

Most SCA tools tell you *"you depend on a package with a known CVE."* VScan
goes further: it builds a **knowledge graph** of your repository (files,
dependencies, functions, call edges, public entry points and documentation),
computes which public entry points actually **reach** which dependencies,
correlates those dependencies against public vulnerability databases, and can
optionally ask an LLM to judge how exposed a reachable finding is, based on your
own docs.

## Pipeline

```
repo ──► scanner ──► reachability ──► correlator ──► agent (optional) ──► report
         (graph)     (entry point →   (OSV, KEV,     (advisory exposure
                      functions →      EPSS, NVD)     assessment)
                      dependencies)
                          └──────────────► dashboard/ (viewer for the scan JSON)
```

1. **Scanner** (`scanner/`): walks the repo (honouring `.gitignore`) and emits a
   typed, JSON-serializable knowledge graph. Deterministic and offline.
   * Dependency manifests: Python (`requirements*.txt`, `pyproject.toml`), npm
     (`package.json`, plus exact versions from `package-lock.json` /
     `pnpm-lock.yaml` when present), PHP (`composer.json`), Go (`go.mod`). The
     resolved tree is also enumerated for **transitive** dependencies — npm
     (`package-lock.json` / `pnpm-lock.yaml`), Go (`// indirect` requires),
     Python (`poetry.lock` / `Pipfile.lock`), PHP (`composer.lock`) — tagged
     `direct=false`. A plain `requirements.txt` carries no direct/transitive
     signal, so every entry there is treated as direct.
   * Code analysis: **Python is deep** (stdlib `ast`, cross-file call resolution
     and single-hop method resolution with a proven receiver). **JavaScript and
     Go resolve calls across files** (JS module imports, Go cross-package);
     **PHP is single-file**. JS/PHP/Go are built on tree-sitter.
   * Entry points: decorator routes (`@app.route`, `@app.get`, `@router.get` ...),
     Django `urlpatterns`, registry-style Python routes (Flask-RESTful
     `add_resource`, `add_url_rule`, FastAPI `add_api_route`, blueprint /
     `APIRouter` + `include_router` prefixes), and Starlette (`Route` list +
     `Mount` + `add_route` + the deprecated `@app.route`). JS (Express / Koa /
     Fastify), PHP (Laravel / Slim / Symfony `#[Route]` attributes) and Go
     (`net/http`, gin, echo, chi, gorilla/mux `HandleFunc().Methods()`, fiber)
     routes are detected; JS and Go link handlers and calls across files, PHP
     within a single file. See the support matrix below.
   * Documentation: README / Markdown / reST / `docs/` / OpenAPI files become
     `doc` nodes, linked to routes and symbols they mention.
2. **Reachability engine** (`scanner/reachability.py`): a pure, deterministic
   BFS from every entry point over `route_to_handler` and `calls` edges. Reports
   which functions and dependencies each entry point reaches, with an example
   path, and gives every dependency (direct or transitive) a three-way verdict
   (below).
3. **Correlator** (`scanner/correlate/`): the only network-touching layer of the
   scanner. Matches dependencies (direct **and** transitive) against **OSV**,
   flags actively exploited CVEs with **CISA KEV**, adds **EPSS** exploit
   probability, and optionally fetches numeric CVSS from **NVD**. Findings are
   joined with reachability and ranked: KEV, then EPSS, then reachability, then
   severity. Results are cached outside the repo (`~/.cache/vscan`,
   overridable with `VSCAN_CACHE_DIR` / `XDG_CACHE_HOME`).
4. **Agent layer** (`scanner/agent/`, opt-in): for findings already proven
   reachable, reads the documentation and route context and writes an
   *advisory* exposure assessment (internet-facing vs. internal, authenticated
   or not). Provider-neutral: any OpenAI-compatible chat-completions endpoint,
   configured purely through environment variables. With no model configured it
   falls back to a deterministic offline heuristic.
5. **Dashboard** (`dashboard/`): a static viewer for the scan graph (see below).

### Graph model

* **Nodes** (`kind`): `file`, `module`, `dependency`, `function`, `entrypoint`,
  `doc`. Stable ids: `dep:<ecosystem>:<name>`, `file:<relpath>`,
  `mod:<module.path>`, `fn:<relpath>:<qualname>`, `ep:<METHOD>:<path>`,
  `doc:<relpath>`.
* **Edges** (`kind`): `imports`, `calls`, `declares`, `route_to_handler`,
  `documents`, `contains`.

### Extension seams

* **Manifest adapters** (`scanner/manifests/`) extract dependencies per
  ecosystem. A new ecosystem is a new `ManifestAdapter` subclass registered in
  the package `__init__`; the orchestrator only calls `adapter_for()`.
* **Language analyzers** (`scanner/analyzers/`) implement the
  `LanguageAnalyzer` interface. A language without an analyzer degrades
  gracefully: its files still appear as `file` nodes.

## Language & framework support

Route detection finds public entry points; taint decides whether attacker
input provably reaches a vulnerable call (see *Finding signals* below). Both
are accurate to the analyzers in `scanner/analyzers/` and `scanner/taint/`.

| Language | Route / framework detection | Taint sources |
|---|---|---|
| **Python** | Flask (`@route`/`@get`, `add_url_rule`, Blueprint prefixes, Flask-RESTful `add_resource`), FastAPI (`@get` …, `APIRouter` + `include_router` prefix, `add_api_route`), Django (`urls.py` `path` / `re_path` / `url`), Starlette (`Route` list + `Mount` + `add_route` + the deprecated `@app.route`) | `request` (Flask / Django), the FastAPI `Request` parameter, and Starlette request reads incl. `await request.json()` / `.form()` / `.body()` |
| **JavaScript** | Express, Koa, Fastify | Express `req` (`req.query` / `.body` / `.params` …), Koa `ctx` (`ctx.query`, `ctx.request.body` …) |
| **Go** | `net/http` (`HandleFunc`), gin, echo, chi, gorilla/mux (`HandleFunc().Methods()`), fiber | `*http.Request` (`FormValue`, `.Form` / `.Header` / `.Body`, `URL.Query()`), `*gin.Context`, `echo.Context`, chi handlers (via `*http.Request`), `mux.Vars`, `*fiber.Ctx` |
| **PHP** | Laravel (`Route::verb`), Slim (`$app->verb`), Symfony (`#[Route]` PHP-8 attribute) | *none* — the PHP analyzer emits no dependency call edges, so there is no sink for taint to reach |

**Call resolution scope:** Python resolves calls across files plus single-hop
method dispatch with a proven receiver; JavaScript resolves across module
imports; Go resolves across packages, including same-package cross-file bare
calls and handlers; PHP is single-file. Every taint verdict is `tainted` or
`not_proven`, and `not_proven` never means "safe" — see *Finding signals* and
*Limitations*.

## Install & usage

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest                       # optional: run the test suite
```

Three subcommands:

```bash
# 1. Build the knowledge graph (JSON) + a summary on stderr.
vscan scan <repo> [-o graph.json]          # default: vscan-graph.json

# 2. Which entry points reach which functions and dependencies.
vscan reachability <repo> [-o result.json] [--json]

# 3. Full scan: correlate against vuln databases, join with reachability, rank.
vscan audit <repo> [-o audit.json] [--json] [--offline] [--nvd] [--explain] [--bundle bundle.json]
                                  [--sarif out.sarif] [--markdown comment.md] [--fail-on LEVEL]
```

| Flag | Applies to | Meaning |
|---|---|---|
| `-o`, `--output` | all | `scan`: graph JSON path. `reachability` / `audit`: optional path to also write the full result as JSON. |
| `--json` | `reachability`, `audit` | Print JSON to stdout instead of the text report. |
| `--offline` | `audit` | Query no network database; still prints the graph and reachability picture. |
| `--nvd` | `audit` | Best-effort NVD numeric CVSS lookups (rate-limited). |
| `--explain` (alias `--assess`) | `audit` | Run the three advisory tiers over the reachable findings and print them: exposure assessment, symbol-level exploitability triage, and dynamic-usage investigation (LLM if configured via the env vars below, otherwise the offline heuristic). |
| `--bundle PATH` | `audit` | Also write a self-contained viewer bundle (graph + reachability + ranked findings + the advisory tiers) as one JSON for the dashboard. Additive; works offline (findings then empty). |
| `--sarif PATH` | `audit` | Also write a SARIF 2.1.0 log of the findings (for GitHub code scanning). Deterministic and offline-friendly; additive, does not affect stdout. |
| `--markdown PATH` | `audit` | Also write a PR-comment-ready markdown summary (impact funnel line plus a table of the top reachable/exploitable findings). Additive. |
| `--fail-on {never,reachable,confirmed,tainted,any}` | `audit` | CI exit code: exit 1 when a finding meets the bar (reachable; `symbol_match` confirmed; tainted/exploitable; or any finding at all). Default `never` (always exit 0). |

### Environment variables

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` | Enable the LLM for the three advisory tiers (`--explain`, and the `--bundle` payload). Any OpenAI-compatible chat-completions endpoint; nothing is hardcoded to a provider. If unset, or on any client error, the offline heuristic runs instead. |
| `NVD_API_KEY` | Optional; read by `--nvd` for better NVD rate limits. |
| `VSCAN_CACHE_DIR` | Optional; override the correlator cache location. |

## MCP server / AI tool

The same library is exposed as an [MCP](https://modelcontextprotocol.io) server
so an LLM agent can navigate a repository through its knowledge graph (instead
of reading files), reason over the vulnerability findings, and drive fixes. The
server wraps the library in process and speaks MCP over stdio (default) or
streamable HTTP (`--transport streamable-http`, see
[Server deployment](#server-deployment-docker-compose)).

```bash
pip install -e ".[mcp]"      # or: pip install "vscan[mcp]"
vscan-mcp                # run the stdio server (also: python -m scanner.mcp)
```

Wire it into an MCP client either via a `.mcp.json` entry:

```json
{
  "mcpServers": {
    "vscan": { "command": "vscan-mcp" }
  }
}
```

or, for clients with a CLI:

```bash
claude mcp add vscan -- vscan-mcp
```

All tools take a `repo_path` and return compact JSON. The first call scans the
repo; the graph is cached per path and reused (pass `refresh=true` to re-scan).
The advisory tiers behind `audit` / `finding_detail` work with no API key via
the offline heuristic, and honour the same `LLM_*` env vars as the CLI when a
model is configured. The twelve tools, grouped by capability:

**Navigate** (replace manual file reading)
- `vscan_scan_overview` — scan + structural map: counts, languages, entry points, top modules/files. The "understand this repo" entry point.
- `vscan_find` — substring search over node name/id/path → node ids.
- `vscan_describe` — full datasheet for a node (function signature/docstring/callers/callees, dependency version/reachability, entry-point reach), replacing opening the file.
- `vscan_call_graph` — expand callers (`in`) or callees (`out`) of a function to N hops.
- `vscan_trace_entrypoint` — forward: the functions and dependencies a route reaches, with example paths.
- `vscan_dep_reachers` — reverse: which entry points reach a dependency, with the three-way verdict ("who can hit this").

**Discuss problems** (reachability-aware findings)
- `vscan_audit` — the headline "what's wrong" tool: ranked findings (reachable + actively-exploited first) with severity/CVSS/KEV/EPSS, verdict, and optional advisory triage + usage.
- `vscan_finding_detail` — deep dive on one vulnerable dependency: every CVE's full text, reachable paths, triage reasoning, usage evidence.

**Fix**
- `vscan_remediation` — for one dependency or all vulnerable ones: current version, smallest fixed version that clears the CVEs, the manifest file and pin to change, reachability priority, and the entry points/paths to re-test after upgrading.
- `vscan_apply_upgrade` — surgically re-pin one dependency in its manifest and return a unified diff (`dry_run=true` by default previews only). Refuses when the pin is ambiguous or a range, pointing at the file/line to edit manually.
- `vscan_verify_fix` — **prove** an upgrade before committing it, without touching the repo. Clears the CVEs by version-math against each advisory's own `fixed_versions`, then applies the upgrade to a throwaway **copy**, re-audits it, and confirms nothing new became reachable/tainted and no existing finding escalated. Needs a successful networked baseline (offline → nothing can be proven). Returns a six-value `verdict`: `unverified_no_baseline`, `no_known_cves`, `cve_not_cleared`, `cve_cleared_regressions_unknown`, `fix_introduces_new_exposure`, or `fix_verified`.
- `vscan_diff` — compare two checkouts (e.g. PR base vs. head) through the identical reachability-/taint-aware pipeline and report which findings a change **resolved**, **introduced**, or **shifted** (reachability / verdict / `symbol_match` / `taint` / version transitions).

An MCP prompt, `audit_and_fix`, scripts the full audit → remediate → preview →
prove loop (`vscan_audit` → `vscan_remediation` → `vscan_apply_upgrade`
dry-run → `vscan_verify_fix`) prioritising `tainted` > `confirmed` >
`reachable`.

## Server deployment (Docker Compose)

`docker-compose.yml` runs two containers:

* `mcp`: the MCP server over streamable HTTP. It has no authentication of its
  own and publishes no host port.
* `caddy`: serves `dashboard/` at `https://$DOMAIN/`, proxies
  `https://$DOMAIN/mcp` to the MCP server only when the request carries
  `Authorization: Bearer $MCP_TOKEN`, and obtains the TLS certificate
  automatically.

The dashboard is public and static. It shows the bundled sample scans, and
"Load a scan" reads the file in the visitor's browser only.

On the server (any Linux host, e.g. a Hetzner Cloud instance):

1. Point a DNS A (and AAAA) record for the domain at the server. If a Hetzner
   firewall is attached, allow inbound TCP 80 and 443 (and UDP 443 for HTTP/3).
2. Install Docker: `curl -fsSL https://get.docker.com | sh`
3. Clone and configure:
   ```bash
   git clone https://github.com/swaggpi/VScan.git && cd VScan
   cp .env.example .env   # set DOMAIN and MCP_TOKEN; optionally LLM_* / NVD_API_KEY
   ```
4. Put the repositories to scan under `./repos`, which is mounted at `/repos`:
   ```bash
   git clone <repo-url> repos/<name>
   chown -R 1000:1000 repos   # only if vscan_apply_upgrade should write (container runs as uid 1000)
   ```
5. Start: `docker compose up -d --build`. Update later with
   `git pull && docker compose up -d --build`.

Connect a client and pass paths as the container sees them (`/repos/<name>`):

```bash
claude mcp add --transport http vscan https://$DOMAIN/mcp \
  --header "Authorization: Bearer $MCP_TOKEN"
```

Clients that cannot send a custom header (for example, those that support only
OAuth for remote servers) cannot connect to this setup.

## Example output

Captured from `samples/vulnerable-app` (a deliberately outdated Python + npm +
PHP + Go sample). Output below is verbatim except for trimming.

`vscan scan samples/vulnerable-app -o graph.json` (summary goes to stderr):

```
vscan scan: samples/vulnerable-app
  files:        11
  modules:      3
  functions:    3
  entrypoints:  2
  docs:         2
  dependencies: 12

  Dependencies:
    - [Go] github.com/gin-gonic/gin v1.6.0 (declared)
    - [PyPI] Flask 0.12.2 (declared)
    - [PyPI] PyYAML 3.13 (declared)
    - [npm] lodash 4.17.4 (resolved)
    ...                                  (12 listed in the real output)

  Entry points:
    - GET /health -> health
    - POST /import -> import_data
```

`vscan reachability samples/vulnerable-app`:

```
GET /health -> fn:app.py:health
  reachable functions: 1
  reachable dependencies:
    - Flask 0.12.2 [PyPI]  (called via flask.jsonify)
      example path: ep:GET:/health -> fn:app.py:health -> dep:PyPI:Flask
  unresolved calls encountered: 0 (reachability is a lower bound -- unresolved call sites are never turned into edges)

POST /import -> fn:app.py:import_data
  reachable functions: 2
  reachable dependencies:
    - Flask 0.12.2 [PyPI]  (called via flask.jsonify)
      example path: ep:POST:/import -> fn:app.py:import_data -> dep:PyPI:Flask
    - PyYAML 3.13 [PyPI]  (called via yaml.load)
      example path: ep:POST:/import -> fn:app.py:import_data -> fn:utils/config_loader.py:load_config -> dep:PyPI:PyYAML
  unresolved calls encountered: 0 (reachability is a lower bound -- unresolved call sites are never turned into edges)

Dependencies reachable from a public entry point:
  - Flask 0.12.2 [PyPI]
  - PyYAML 3.13 [PyPI]

Declared but not reachable from any entry point:
  - github.com/gin-gonic/gin v1.6.0 [Go] (no resolved call site at all)
  - lodash 4.17.4 [npm] (no resolved call site at all)
  ...                                  (10 listed in the real output)
```

`vscan audit samples/vulnerable-app --offline` (deterministic, no network):

```
vscan audit: samples/vulnerable-app
========================================================================
! Offline mode: no vulnerability database was queried.

Summary
  dependencies scanned:          12
  vulnerable dependencies:       0
  total vulnerabilities:         0
  reachable vulnerabilities:     0
  actively exploited (KEV):      0
  high EPSS (>= 0.5):            0

Vulnerability data was not available (see notice above). Showing the dependency and reachability picture only:

Reachability (dependencies reachable from a public entry point):
  - Flask 0.12.2 [PyPI]
  - PyYAML 3.13 [PyPI]

Three-way verdict (per declared dependency):
  reachable:              2
  potentially reachable:  0
  unreachable:            10
```

Adding `--explain` (still offline, so the deterministic heuristic runs) appends
**three** advisory sections — exposure assessment, exploitability triage, and
dynamic-usage investigation. Only the first is shown here (the others follow the
same format):

```
Exposure assessment (advisory tier)
------------------------------------------------------------------------
Note: using the offline heuristic (no model configured). Enable the model by setting LLM_BASE_URL, LLM_API_KEY and LLM_MODEL.
This tier is ADVISORY ONLY: it does not change the reachability verdict.

 2. PyYAML -- (no advisory id)
    reachable via: POST /import
    exposure: internet-facing   authentication: none
    rationale: Documentation for POST /import contains the phrase "any user", indicating exposure=internet-facing / authentication=none.
    summary: PyYAML 3.13 (the vulnerable dependency) is reachable from POST /import; docs describe it as internet-facing and unauthenticated -- treat as externally exploitable.
    [provenance=offline-heuristic; advisory=True]
```

(Entry 1, Flask, trimmed.) With `--offline` there is no vulnerability data, so
the "vulnerable dependency" wording and "(no advisory id)" reflect the
assessment being run over reachable dependencies rather than real advisories.
Without `--offline`, `audit` needs network access to api.osv.dev, CISA and
FIRST; it then prints a ranked "Findings" list (CVE ids, KEV badge, severity,
EPSS, reachability, fixed-in versions). That online output is not reproduced
here.

## Reachability verdicts and the soundness rule

Every dependency gets one of three verdicts:

* **`reachable`**: a path of *resolved* `route_to_handler` / `calls` edges runs
  from a public entry point to the dependency.
* **`unreachable`**: no resolved path reaches it **and** the whole reachable
  code region (every function reachable from any entry point) contains **zero**
  unresolved call sites.
* **`potentially_reachable`**: no resolved path reaches it, but at least one
  unresolved call exists on the reachable region, so an unseen edge might lead
  there. We refuse to rule it out.

Precisely: a non-reached **direct** dependency is `unreachable` if and only if
the sum of unresolved-call counts over every function reachable from any entry
point is zero. Otherwise it is `potentially_reachable`. The per-entry-point
verdict applies the same rule to that entry point's reachable set. A **transitive**
dependency is the one exception: when not reached by a resolved path it is
*always* `potentially_reachable`, never `unreachable`, because we do not analyse
a dependency's internals and so cannot prove it unused.

## Finding signals: symbol_match, taint, and the impact funnel

Reachability answers "can an entry point reach this *package*?". Two further
deterministic, offline signals (no API key, no network) narrow that down per
finding. Both are derived from the reachability result and can only refine it,
never override it.

**`symbol_match`** (always on) is a 3-tier signal on every finding, comparing the
advisory's named vulnerable function against the reachable call paths:

* `confirmed`: the advisory's vulnerable function is on a reachable path.
* `package_reachable`: the package is reachable, but the specific vulnerable
  function is unconfirmed (no resolved call to a function the advisory names). Also used when reachability is only `potentially_reachable`.
* `no_path`: the dependency is not reachable.

**`taint`** (Python, JavaScript, and Go) asks whether attacker-controlled input
provably reaches the vulnerable call. `tainted` means web input — Python
(Flask / FastAPI / Django `request`, Starlette request), JavaScript
(Express / Koa `req`/`ctx`), or Go (net/http `*http.Request`, gin, echo, chi,
gorilla/mux `mux.Vars`, fiber) — flows into that call; otherwise `not_proven`.
`not_proven` is **not** "safe": it means no flow was proven. It is a strict
refinement: `tainted` implies `symbol_match: confirmed`, which implies
`reachable`. Known misses (reported as `not_proven`, never guessed): flows
laundered through a return value, `*args` forwarding, computed/dynamic member
access, callback bodies, and instance methods called across files in Python.

**Impact funnel**: `audit` prints one summary line, and the dashboard shows it
as a funnel, narrowing from every dependency (direct + transitive) to what is
actually exploitable:

```
Funnel: N deps · M known CVEs · R reachable · C vulnerable-function confirmed · T exploitable (attacker input reaches the call)
```

`--sarif`, `--markdown` and `--fail-on` (see the flag table above) export these
signals for CI; the GitHub Action below wires them together.

## Design principle

**An edge or verdict is only asserted when it is soundly resolved. Unknowns are
recorded, never guessed.** A wrong edge (false reachability) is the worst
failure for this kind of tool, so when a call target cannot be determined, the
analyzer stores it as an `unresolved` call on the source function instead of
inventing an edge. Reachability traverses only edges that exist.

The LLM is **advisory only**. It reads docs and route context for findings the
deterministic engine has already proven reachable; it cannot add or change an
edge, a reachability verdict, or a finding's `reachable` flag. Every assessment
carries `advisory=True` and a `provenance` (`llm` or `offline-heuristic`), and
unsure or unevidenced cases resolve to `unknown`.

### Python call resolution: what is and is NOT resolved

Call resolution uses a conservative symbol table, not a points-to analysis.

**Resolved**

* `import x` / `import x as y` / `import a.b.c`, mapped to an intra-repo module
  or a dependency.
* `from m import f` / `... as g`, including relative imports, mapped to an
  intra-repo function, submodule, or dependency symbol.
* Direct calls to imported or sibling functions (`f(...)`).
* Attribute calls through an import alias (`y.load(...)` with `import yaml as y`
  gives dependency `PyYAML`, `symbol=yaml.load`; `mod.func(...)` gives an
  intra-repo function).
* Simple one-hop local aliasing (`f = some_func; f()`).
* **Single-hop method dispatch with a _proven_ receiver class:** `self.m(...)`
  inside a method of class `C` resolves to `C.m`; `v.m(...)` where `v` comes from
  an unambiguous `v = Cls(...)`, and `Cls(...).m(...)`, resolve when `Cls` is a
  local or imported class and `m` is defined directly on it. The receiver is
  never guessed — an unprovable one stays unresolved.
* An import-name to PyPI-package map for well-known mismatches (`yaml`→`PyYAML`,
  `dateutil`→`python-dateutil`, `psycopg2`→`psycopg2-binary`, `jwt`→`PyJWT`,
  `bs4`→`beautifulsoup4`, `PIL`→`Pillow`, `sklearn`→`scikit-learn`, ...);
  otherwise import name equals package name (case-normalised).

**Not resolved (recorded, never guessed)**

* **Multi-hop** or unprovable method dispatch (`a.b.method()`, a method defined
  only on a base class, a receiver whose class can't be proven).
* Calls through data structures or return values (`handlers[key]()`,
  `factory().run()`).
* Dynamic dispatch (`getattr(obj, name)()`, `globals()[...]()`).
* Names rebound by control flow, closure/comprehension scoping subtleties, or
  `*` imports.

The JS and Go analyzers follow the same rule across files (JS module imports, Go
cross-package); PHP resolves within a single file. Everything unresolved is
recorded as `unresolved_calls`.

## Limitations

* **PHP is single-file.** Python resolves calls across files and single-hop
  methods; JavaScript resolves across module imports and Go across packages. PHP
  remains single-file (a route whose handler lives in another PHP file is not
  linked to it), because PHP's dynamic autoloading makes cross-file resolution
  unsound to assert.
* **PHP emits no dependency call or import edges.** A PHP namespace does not
  reliably map to a Composer package, so the analyzer records `use` statements
  but does not guess an edge. PHP dependencies therefore appear as declared but
  never as reached.
* **Reachability is a lower bound.** It under-approximates what code can do.
  Unresolved calls are not edges. An `unreachable` verdict is only as complete
  as the entry points and languages the analyzers could see: in the sample
  above, the npm, Go and PHP packages show as unreachable because no detected
  entry point reaches them, not because they were proven unused.
* **OSV needs exact versions.** Only dependencies with a single pinned version
  are queried; ranges such as `>=2.20.0` (e.g. `requests` in the sample) are
  skipped rather than guessed. Python and PHP versions are as *declared*; npm
  uses the lockfile's resolved version when one exists.
* **Transitive dependencies are enumerated but never ruled out.** The resolved
  tree from lockfiles / `// indirect` requires is walked (npm, Go, Python
  `poetry.lock` / `Pipfile.lock`, PHP `composer.lock`) and those packages become
  graph nodes tagged `direct=false`, so they *are* correlated against OSV. But a
  transitive dep that no resolved path reaches is always `potentially_reachable`,
  **never** `unreachable`: we do not analyse a dependency's internals, so we
  cannot prove which of its own transitive edges a direct dependency exercises
  (the soundness rule). A plain `requirements.txt` carries no direct/transitive
  signal, so its entries are all treated as direct and cannot be split. The
  summary object exposes `direct_dependencies` / `transitive_dependencies`
  counts, and the dashboard has a transitive toggle.
* **Taint covers Python, JavaScript, and Go, and is conservative.** PHP findings
  always get `taint: not_proven` (the PHP analyzer is single-file and emits no
  dependency call edges, so there is no sink for taint to reach). In the three
  supported languages, flows laundered through a call's return value, and other
  grammar-specific hard cases (e.g. Python `*args`/cross-file instance methods,
  computed/dynamic member access, callback bodies), are not followed — so
  `not_proven` means "not proven", never "safe".
* **The advisory tiers are advisory.** They are only as good as your docs/CVE
  text, and with the offline heuristic fall back to simple phrase/symbol
  matching. They never change a deterministic reachability verdict or call edge.
* The dashboard shows the structural graph, reachability traces, **and** — when
  fed an `audit --bundle` JSON — the ranked vulnerability findings overlaid on
  the graph (reachable-and-vulnerable dependencies are the top signal), with the
  advisory exploitability-triage and dynamic-usage context per dependency, the
  impact funnel, and each finding's `symbol_match` / `taint` escalation.

## Dashboard

`dashboard/index.html` is a static, no-build reachability viewer: open it in a
browser (it pulls Cytoscape and fonts from a CDN), pick an entry point to
highlight the path to the dependencies it reaches, or use "Load a scan" to open
a graph JSON produced by `vscan scan -o`. A bundled sample graph loads by
default. Fed an `audit --bundle` JSON it additionally shows the ranked findings
overlaid on the graph, the per-finding `symbol_match` / `taint` **escalation
view**, the **impact funnel**, and a **transitive-dependency toggle**.

<!-- integration / credits section added separately -->

## Continuous integration (GitHub Action)

A composite action runs the scan in CI, uploads the findings to GitHub code
scanning, and posts a reachability funnel as a PR comment. Minimal usage:

```yaml
# .github/workflows/vscan.yml
name: VScan
on:
  pull_request: {}
  push:
    branches: [main]

permissions:
  contents: read            # checkout
  security-events: write    # upload SARIF to code scanning
  pull-requests: write      # post/update the PR comment

jobs:
  vscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: swaggpi/VScan@main
        with:
          path: .
          fail-on: reachable      # never | reachable | confirmed | tainted | any
```

Key inputs (all optional): `path` (default `.`), `fail-on` (default
`reachable`), `offline` (default `false`), `comment` (default `true`),
`upload-sarif` (default `true`), `python-version` (default `3.12`).

The `permissions` block is required: `security-events: write` for the SARIF
upload and `pull-requests: write` for the PR comment. Drop either permission (or
set `upload-sarif: false` / `comment: false`) to skip that step.

`fail-on` controls when the job fails — it mirrors the scanner's funnel:

| `fail-on` | Job fails when there is a finding that is… |
|---|---|
| `never` | never — report only |
| `reachable` | reachable from a public entry point |
| `confirmed` | reachable **and** symbol-confirmed in the vulnerable function |
| `tainted` | exploitable — attacker input reaches the vulnerable call |
| `any` | any known CVE in a declared dependency, reachable or not |

Results show up in two places: the repo's **Security → Code scanning** tab
(from the uploaded SARIF) and as a single PR comment that is updated in place on
each push (no comment spam). The scan runs `--offline` when `offline: true`,
which analyzes reachability without querying any network vulnerability database.

## License

MIT
