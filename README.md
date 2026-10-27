# vulnreach

A reachability-aware dependency vulnerability scanner.

Most SCA tools tell you *"you depend on a package with a known CVE."* `vulnreach`
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
     `pnpm-lock.yaml` when present), PHP (`composer.json`), Go (`go.mod`).
   * Code analysis: **Python is deep** (stdlib `ast`, cross-file call resolution
     and single-hop method resolution with a proven receiver). **JavaScript and
     Go resolve calls across files** (JS module imports, Go cross-package);
     **PHP is single-file**. JS/PHP/Go are built on tree-sitter.
   * Entry points: decorator routes (`@app.route`, `@app.get`, `@router.get` ...),
     Django `urlpatterns`, and registry-style Python routes (Flask-RESTful
     `add_resource`, `add_url_rule`, blueprint/router prefixes). JS (Express /
     Koa / Fastify), PHP (Laravel / Slim / Symfony attributes) and Go (gin /
     echo / chi / mux / `net/http`) routes are detected; JS and Go link handlers
     and calls across files, PHP within a single file.
   * Documentation: README / Markdown / reST / `docs/` / OpenAPI files become
     `doc` nodes, linked to routes and symbols they mention.
2. **Reachability engine** (`scanner/reachability.py`): a pure, deterministic
   BFS from every entry point over `route_to_handler` and `calls` edges. Reports
   which functions and dependencies each entry point reaches, with an example
   path, and gives every declared dependency a three-way verdict (below).
3. **Correlator** (`scanner/correlate/`): the only network-touching layer of the
   scanner. Matches dependencies against **OSV**, flags actively exploited CVEs
   with **CISA KEV**, adds **EPSS** exploit probability, and optionally fetches
   numeric CVSS from **NVD**. Findings are joined with reachability and ranked:
   KEV, then EPSS, then reachability, then severity. Results are cached outside
   the repo (`~/.cache/vulnreach`, overridable with `VULNREACH_CACHE_DIR` /
   `XDG_CACHE_HOME`).
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
vulnreach scan <repo> [-o graph.json]          # default: vulnreach-graph.json

# 2. Which entry points reach which functions and dependencies.
vulnreach reachability <repo> [-o result.json] [--json]

# 3. Full scan: correlate against vuln databases, join with reachability, rank.
vulnreach audit <repo> [-o audit.json] [--json] [--offline] [--nvd] [--explain] [--bundle bundle.json]
```

| Flag | Applies to | Meaning |
|---|---|---|
| `-o`, `--output` | all | `scan`: graph JSON path. `reachability` / `audit`: optional path to also write the full result as JSON. |
| `--json` | `reachability`, `audit` | Print JSON to stdout instead of the text report. |
| `--offline` | `audit` | Query no network database; still prints the graph and reachability picture. |
| `--nvd` | `audit` | Best-effort NVD numeric CVSS lookups (rate-limited). |
| `--explain` (alias `--assess`) | `audit` | Run the three advisory tiers over the reachable findings and print them: exposure assessment, symbol-level exploitability triage, and dynamic-usage investigation (LLM if configured via the env vars below, otherwise the offline heuristic). |
| `--bundle PATH` | `audit` | Also write a self-contained viewer bundle (graph + reachability + ranked findings + the advisory tiers) as one JSON for the dashboard. Additive; works offline (findings then empty). |

### Environment variables

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` | Enable the LLM for the three advisory tiers (`--explain`, and the `--bundle` payload). Any OpenAI-compatible chat-completions endpoint; nothing is hardcoded to a provider. If unset, or on any client error, the offline heuristic runs instead. |
| `NVD_API_KEY` | Optional; read by `--nvd` for better NVD rate limits. |
| `VULNREACH_CACHE_DIR` | Optional; override the correlator cache location. |

## Example output

Captured from `samples/vulnerable-app` (a deliberately outdated Python + npm +
PHP + Go sample). Output below is verbatim except for trimming.

`vulnreach scan samples/vulnerable-app -o graph.json` (summary goes to stderr):

```
vulnreach scan: samples/vulnerable-app
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

`vulnreach reachability samples/vulnerable-app`:

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

`vulnreach audit samples/vulnerable-app --offline` (deterministic, no network):

```
vulnreach audit: samples/vulnerable-app
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

Every declared dependency gets one of three verdicts:

* **`reachable`**: a path of *resolved* `route_to_handler` / `calls` edges runs
  from a public entry point to the dependency.
* **`unreachable`**: no resolved path reaches it **and** the whole reachable
  code region (every function reachable from any entry point) contains **zero**
  unresolved call sites.
* **`potentially_reachable`**: no resolved path reaches it, but at least one
  unresolved call exists on the reachable region, so an unseen edge might lead
  there. We refuse to rule it out.

Precisely: a non-reached dependency is `unreachable` if and only if the sum of
unresolved-call counts over every function reachable from any entry point is
zero. Otherwise it is `potentially_reachable`. The per-entry-point verdict
applies the same rule to that entry point's reachable set.

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
* **Transitive dependencies are not over-claimed.** The graph contains the
  dependencies *declared* in manifests (lockfiles only supply exact versions for
  those). Transitive packages are not graph nodes, so they are neither matched
  against OSV nor reported as reachable, and reachability is never inferred
  through a dependency's internals.
* **The advisory tiers are advisory.** They are only as good as your docs/CVE
  text, and with the offline heuristic fall back to simple phrase/symbol
  matching. They never change a deterministic reachability verdict or call edge.
* The dashboard shows the structural graph, reachability traces, **and** — when
  fed an `audit --bundle` JSON — the ranked vulnerability findings overlaid on
  the graph (reachable-and-vulnerable dependencies are the top signal), with the
  advisory exploitability-triage and dynamic-usage context per dependency.

## Dashboard

`dashboard/index.html` is a static, no-build reachability viewer: open it in a
browser (it pulls Cytoscape and fonts from a CDN), pick an entry point to
highlight the path to the dependencies it reaches, or use "Load a scan" to open
a graph JSON produced by `vulnreach scan -o`. A bundled sample graph loads by
default.

<!-- integration / credits section added separately -->

## License

MIT
