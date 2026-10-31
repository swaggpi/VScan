# transitive-app

A minimal Node sample that exercises **transitive dependency** scanning: the
scanner surfaces CVE-bearing packages from the whole resolved dependency tree,
not just the ones the manifest declares -- while keeping reachability **sound**.

## Ground truth (hand-verified)

| package  | kind       | source                                   | `direct` |
|----------|------------|------------------------------------------|----------|
| express  | **direct** | declared in `package.json`               | `True`   |
| minimist | transitive | resolved only by `package-lock.json`     | `False`  |
| qs       | transitive | resolved only by `package-lock.json`     | `False`  |

`package.json` declares exactly one dependency (`express`). The lockfile
(`package-lock.json`, lockfileVersion 3, `packages` map) resolves `minimist`
and `qs` as well -- packages the manifest never names. The scanner emits all
three as `dependency` nodes; the two the manifest does not declare carry node
attr `direct=False`.

## Reachability ground truth (the soundness crux)

`server.js` wires `GET /health` to a named handler whose body makes **no
calls**, so the reachable region is **fully resolved**. None of the three deps
has an incoming call edge. The verdicts are therefore:

| package  | verdict                 | why                                                      |
|----------|-------------------------|----------------------------------------------------------|
| express  | `unreachable`           | direct dep, no call edge, region fully resolved          |
| minimist | `potentially_reachable` | transitive: a reachable top-level dep *might* reach it   |
| qs       | `potentially_reachable` | transitive: same -- UNKNOWN, so never ruled unreachable  |

Same region, same edge-absence -- the only thing that differs is the `direct`
flag. A transitive dep must **never** be marked `unreachable`: we do not analyze
a top-level dependency's internals, so whether a reachable top-level dep in turn
reaches a transitive dep is unknown, and the honest verdict is
`potentially_reachable`.

## Follow-ups (out of scope this round)

Transitive resolution currently covers npm (`package-lock.json` /
`pnpm-lock.yaml`) and Go (`// indirect` requires in `go.mod`). Not yet parsed:
PHP `composer.lock` and Python `poetry.lock` / `Pipfile.lock` -- adding those
adapters is the natural next step.
