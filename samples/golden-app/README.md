# golden-app — analyzer ground-truth fixture

A small Flask app whose every connection is **known in advance**, so the scanner
can be checked against a hand-verified answer key. It deliberately packs in the
hard resolution cases (positive *and* negative), and `tests/test_golden_fixture.py`
asserts the scanner reproduces exactly this table. When the analyzer changes,
this test tells you whether a real edge broke or a false edge appeared.

Everything here is a toy: the deps are declared in `requirements.txt` but never
installed, and the code is never run.

## Entry points (5)

| Route | Handler | Route style exercised |
|-------|---------|-----------------------|
| `GET /decorated` | `app.decorated` | `@app.route` decorator, default verb |
| `POST /submit` | `app.submit` | `@app.route(..., methods=["POST"])` |
| `GET /fetch` | `app.fetch` | decorator, default verb |
| `GET /added` | `app.added` | imperative `app.add_url_rule(...)` |
| `GET /api/items` | `app.list_items` | `Blueprint` mounted at `url_prefix="/api"` |

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
| `PyYAML` | called on the `POST /submit` chain | **reachable** |
| `requests` | called on the `GET /fetch` chain | **reachable** |
| `python-dateutil` | called on the `GET /api/items` chain | **reachable** |
| `Flask` | used only at module level, not inside a routed function | **unreachable** |
| `urllib3` | called only from non-routed `offline.sync` | **unreachable** |
| `click` | imported but never called | **unreachable** |
| `itsdangerous` | declared in `requirements.txt`, never imported (declares-only node) | **unreachable** |

The reachable region is **fully resolved**, which is what lets the four
non-reached deps earn a definite `unreachable` verdict (not merely
`potentially_reachable`).

Headline example path:

```
POST /submit → app.submit → services.ingest → services.load_yaml → PyYAML
```
