# transitive-poetry

A minimal Poetry sample that exercises **transitive dependency** scanning for
Python: the scanner surfaces packages from the whole resolved `poetry.lock` tree,
not just the ones `pyproject.toml` declares -- while keeping reachability **sound**.

## Ground truth (hand-verified)

| package  | kind       | source                                      | `direct` |
|----------|------------|---------------------------------------------|----------|
| requests | **direct** | declared in `[tool.poetry.dependencies]`    | `True`   |
| PyYAML   | **direct** | declared in `[tool.poetry.dependencies]`    | `True`   |
| certifi  | transitive | resolved only by `poetry.lock`              | `False`  |
| urllib3  | transitive | resolved only by `poetry.lock`              | `False`  |

`pyproject.toml` declares two dependencies (`requests`, `PyYAML`); the
interpreter constraint `python` is not a dependency. `poetry.lock` resolves
`certifi` and `urllib3` as well -- packages the manifest never names -- so they
become `dependency` nodes with `direct=False`.

### PEP 503 normalization

`pyproject.toml` declares `PyYAML`; `poetry.lock` lists the same package as
`pyyaml`. The declared and locked names are compared PEP 503-normalised
(lowercase, `_`/`.`/`-` runs collapsed), so `pyyaml` is recognised as the
already-declared `PyYAML` and is **not** double-emitted as a transitive
`direct=False` node. There is exactly one node, `dep:PyPI:PyYAML`, `direct=True`.

## Reachability ground truth (the soundness crux)

`app.py` wires `GET /health` to a handler whose body makes **no calls**, so the
reachable region is **fully resolved**. None of the deps has an incoming call
edge. The verdicts are therefore:

| package  | verdict                 | why                                                              |
|----------|-------------------------|------------------------------------------------------------------|
| requests | `unreachable`           | direct dep, no call edge, region fully resolved                  |
| PyYAML   | `unreachable`           | direct dep, no call edge, region fully resolved                  |
| certifi  | `potentially_reachable` | transitive: a reachable top-level dep *might* reach it           |
| urllib3  | `potentially_reachable` | transitive: same -- UNKNOWN, so never ruled unreachable          |

Same region, same edge-absence -- the only thing that differs is the `direct`
flag. A transitive dep must **never** be marked `unreachable`: we do not analyze
a top-level dependency's internals, so whether a reachable top-level dep in turn
reaches a transitive dep is unknown, and the honest verdict is
`potentially_reachable`.
