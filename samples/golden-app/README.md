# golden-app — analyzer ground-truth fixture

A small Flask app whose every connection is **known in advance**, so the scanner
can be checked against a hand-verified answer key. It deliberately packs in the
hard resolution cases (positive *and* negative), and `tests/test_golden_fixture.py`
asserts the scanner reproduces exactly this table. When the analyzer changes,
this test tells you whether a real edge broke or a false edge appeared.

Everything here is a toy: the deps are declared in `requirements.txt` but never
installed, and the code is never run.

## Entry points (8)

| Route | Handler | Route style exercised |
|-------|---------|-----------------------|
| `GET /decorated` | `app.decorated` | `@app.route` decorator, default verb |
| `POST /submit` | `app.submit` | `@app.route(..., methods=["POST"])` |
| `GET /fetch` | `app.fetch` | decorator, default verb |
| `GET /added` | `app.added` | imperative `app.add_url_rule(...)` |
| `GET /api/items` | `app.list_items` | `Blueprint` mounted at `url_prefix="/api"` |
| `POST /load` | `app.load_config` | taint fixture — tainted into PyYAML |
| `GET /echo` | `app.echo` | taint fixture — source read, no sink |
| `GET /proxy` | `app.proxy` | taint fixture — shadow (constant reaches sink) |

## Call edges that MUST resolve

Function → function:

- `app.submit → services.ingest → services.load_yaml` (cross-file, then same-file)
- `app.fetch → services.fetch_remote`
- `app.list_items → services.parse_dates`
- `app.decorated → services.describe` and `app.added → services.describe`
- `store.Store.save → services.persist` — a cross-file **module-level** call made
  from *inside a method body*
- `store.Store.save → store.Store._validate` — a **self-method** call
  (`self._validate(...)`): resolved because `self` is the method's first
  parameter and `_validate` is defined on the same class
- `offline.bootstrap → store.Store.save` — an **instance method** call on a
  **cross-file imported class** (`Store().save(...)` with `from store import
  Store`): resolved because the constructor names a known class and `save` is a
  method that class defines

Function → dependency (with the symbol that proves the link):

- `services.load_yaml → PyYAML` via `import yaml` + `yaml.safe_load`
- `services.fetch_remote → requests` via `requests.get`
- `services.parse_dates → python-dateutil` via `from dateutil import parser as dtp`
  + `dtp.parse` — an **aliased-from import** *and* a **distribution/import
  name mismatch** (`python-dateutil` ↔ `dateutil`)
- `offline.sync → urllib3` via `urllib3.PoolManager` (but `sync` is not routed)
- `mod:app → Flask` (module-level framework use)

## Connections that MUST NOT appear (no false edges)

The soundness core: an edge is asserted only when the receiver is proven. These
must all be **absent**:

- `app.transform → PyYAML` — the parameter `yaml` **shadows** the import, so
  `yaml.load` is a call on the parameter, not the package.
- `app.rebind → PyYAML` — a local `yaml` is **rebound** to another object first.
- `offline.run_plugin → (any dep)` — the target is loaded **dynamically by name**
  (`importlib.import_module`), which is unknowable statically.
- any edge to `click` — it is **imported but never called** (imported-only).

### Resolved method calls (single-hop, receiver proven)

Instance / `self` **method calls** resolve only when the receiver's class is
**proven**, never guessed. The two edges above exercise this:

- `store.Store.save → store.Store._validate` — `self._validate(...)`, where
  `self` is the method's first parameter (and is not rebound) and `_validate`
  is a method of the same class.
- `offline.bootstrap → store.Store.save` — `Store().save(...)`, where `Store`
  is `from store import Store` (a known cross-file class) and `save` is a method
  that class defines.

These sit in the non-routed `offline`/`store` modules, so even though they now
resolve they stay out of the reachable region (bootstrap/Store are never routed).

### Still unresolved by design (documented, not a bug)

The resolver stays sound by refusing anything it cannot prove. These remain
**absent** — the analyzer never fabricates an edge for them:

- **Multi-hop** attribute dispatch (`self.x.y()`, `obj.attr.method()`): no
  instance-attribute typing.
- A method **inherited from a base class** (no MRO modelling): only methods
  defined *directly* on the resolved class are matched.
- A receiver whose class is **not proven**: a call on a parameter, on a var with
  more than one possible constructor, or on an externally-typed value.
- **Dynamic dispatch** (`offline.run_plugin`): a module loaded by name at
  runtime is unknowable statically.

## Dependencies (7) and reachability verdicts

| Dependency | How it's wired | Verdict |
|------------|----------------|---------|
| `PyYAML` | called on the `POST /submit` and `POST /load` chains | **reachable** |
| `requests` | called on the `GET /fetch` and `GET /proxy` chains | **reachable** |
| `python-dateutil` | called on the `GET /api/items` chain | **reachable** |
| `Flask` | `request.get_json` / `request.args.get` inside routed handlers | **reachable** |
| `urllib3` | called only from non-routed `offline.sync` | **unreachable** |
| `click` | imported but never called | **unreachable** |
| `itsdangerous` | declared in `requirements.txt`, never imported (declares-only node) | **unreachable** |

The reachable region is **fully resolved**, which is what lets the three
non-reached deps earn a definite `unreachable` verdict (not merely
`potentially_reachable`). Flask is reachable because the taint-fixture handlers
read the Flask `request` object, which the analyzer resolves as calls into the
Flask distribution.

Headline example path:

```
POST /submit → app.submit → services.ingest → services.load_yaml → PyYAML
```

## Taint ground truth (`scanner/taint.py`)

The taint pass asks a stronger question than reachability: does **attacker-
controlled input at a web handler flow, hop by hop, into a call into the dep**?
It is derived and additive — it never changes a reachability verdict,
`symbol_match`, ranking, or any summary counter. Default is `not_proven` (never
"safe"); only a fully proven source→sink flow is `tainted`.

| Dependency | Taint | Why |
|------------|-------|-----|
| `PyYAML` | **tainted** | `POST /load`: `request.get_json()` → `services.parse_config` → `services.load_yaml` → `yaml.safe_load(raw)`. Every hop is a proven argument binding. |
| `requests` | `not_proven` | Reached only with constant URLs (`GET /fetch`, `GET /proxy`). In `/proxy` a request source **is** read into `requested`, but the value passed to `fetch_remote` is a pinned constant — the tainted value never reaches the sink. |
| `python-dateutil` | `not_proven` | Reached via `GET /api/items` with a constant list literal. |
| `Flask` | `not_proven` | Flask is the **source** library (it produces attacker data); no attacker value flows *into* a Flask sink here. |

Negatives exercised (all must stay `not_proven`):

- **No sink** — `GET /echo` reads `request.args.get("q")` but only echoes it back
  in a local dict; it reaches no dependency call.
- **Shadow / constant-at-sink** — `GET /proxy` reads a real request source into
  `requested` but forwards a constant `target` to the `requests` sink. A name is
  never tainted merely because it looks like request data; only a proven flow of
  attacker data counts.
- **Constant on the reachable chain** — `POST /submit` reaches the very same
  `yaml.safe_load` sink as `/load`, but with the constant `"a: 1"`, so that path
  alone proves nothing (PyYAML is tainted only because the `/load` path does).
