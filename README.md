# vulnreach

A reachability-aware dependency vulnerability scanner.

Most SCA tools tell you *"you depend on a package with a known CVE."* `vulnreach`
goes further: it builds a **knowledge graph** of your repository — files,
dependencies, functions, call edges, public entry points, and documentation —
then uses it to reason about whether a known vulnerability is actually
**reachable** from an externally-exposed entry point in *your* code.

## Status

Early work in progress. Current focus: the **scanner** (layer 1) — the
deterministic pass that builds the knowledge graph.

## Layers

1. **Scanner** — walk a repo, build a typed knowledge graph (deps, AST, routes, docs).
2. **Correlator** — match dependencies against public vulnerability databases (OSV, NVD, CISA KEV, EPSS).
3. **Reachability** — reason over the graph to judge whether each finding is reachable and exposed.

A dashboard surfaces findings ranked by real-world risk.

## Scanner (layer 1)

The scanner is a deterministic, **offline** pass: no network calls, no
vulnerability data. It walks a repository and emits a typed, JSON-serializable
knowledge graph of files, dependencies, modules, functions, call edges, public
entry points and documentation.

### Install & run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Scan a repository (writes vulnreach-graph.json by default):
vulnreach scan samples/vulnerable-app -o graph.json
```

A human-readable summary (file/dependency/function/entrypoint/doc counts, the
dependency list, and the route table) is printed to stderr; the graph JSON is
written to the `-o` path.

### Graph model

* **Nodes** (`kind`): `file`, `module`, `dependency`, `function`, `entrypoint`,
  `doc`. Stable ids: `dep:<ecosystem>:<name>`, `file:<relpath>`,
  `mod:<module.path>`, `fn:<relpath>:<qualname>`, `ep:<METHOD>:<path>`,
  `doc:<relpath>`.
* **Edges** (`kind`): `imports`, `calls`, `declares`, `route_to_handler`,
  `documents`, `contains`.

### Extension seams

* **Manifest adapters** (`scanner/manifests/`) extract dependencies per
  ecosystem. Python and JavaScript are deep (JS resolves exact versions from
  the lockfile); PHP and Go are thin (declared versions). A new ecosystem is a
  new `ManifestAdapter` subclass registered in the package `__init__`; the
  orchestrator only ever calls `adapter_for()`.
* **Language analyzers** (`scanner/analyzers/`) turn source into graph
  structure. Only Python is implemented, and deeply (full stdlib-`ast`
  analysis). JS/Go/PHP analyzers plug into the `LanguageAnalyzer` interface;
  their absence degrades gracefully (files still appear as `file` nodes).

### Python call resolution — what is and is NOT resolved

Call resolution uses a conservative symbol table, not a points-to analysis.
Where a target cannot be determined it is recorded as an `unresolved` attribute
on the source function node rather than guessed — a wrong edge is worse than a
missing one for reachability reasoning.

**Resolved**

* `import x` / `import x as y` / `import a.b.c`, mapped to an intra-repo module
  or a dependency.
* `from m import f` / `... as g`, including relative imports (`from .`,
  `from ..pkg`), mapped to an intra-repo function, submodule, or dependency
  symbol.
* Direct calls to imported or sibling functions (`f(...)`).
* Attribute calls through an import alias (`y.load(...)` with `import yaml as y`
  → dependency `PyYAML`, `symbol=yaml.load`; `mod.func(...)` → intra-repo
  function).
* Simple one-hop local aliasing (`f = some_func; f()`).
* A small import-name → PyPI-package map for well-known mismatches
  (`yaml`→`PyYAML`, `bs4`→`beautifulsoup4`, `cv2`→`opencv-python`,
  `PIL`→`Pillow`, `sklearn`→`scikit-learn`); otherwise import name == package
  name (case-normalised).

**Not resolved (recorded, never guessed)**

* Method dispatch on instances (`self.x()`, `obj.method()`) — no type inference.
* Calls through data structures or return values (`handlers[key]()`,
  `factory().run()`).
* Dynamic dispatch (`getattr(obj, name)()`, `globals()[...]()`).
* Names rebound by control flow, closure/comprehension scoping subtleties, or
  `*` imports.

A full inter-procedural points-to analysis (type/instance modelling,
call-through-data) is the clear future deepening; the `unresolved` records mark
exactly where it plugs in.

### Entry points

Detects `@app.route(..., methods=[...])`, `@app.get/post/...`,
`@router.get(...)` (Flask/FastAPI style), and Django `urlpatterns` with
`path()`/`re_path()`, capturing HTTP method(s) and path.

## License

MIT
