# js-taint-app — JavaScript taint fixture

A minimal Express app whose routes are hand-verified for the sound JavaScript
taint pass (`scanner/taint/javascript.py`). The taint pass asks one question and
only answers it when fully proven:

> Does attacker-controlled request input at a route handler flow, hop by hop,
> into a call that lands in a vulnerable npm dependency?

The cardinal rule: a MISSED flow is acceptable; a FALSE `tainted` is a critical
failure. Everything defaults to `not_proven` (never "safe").

## Dependencies

| package  | why it is here                                        |
| -------- | ----------------------------------------------------- |
| express  | the web framework (route sources)                     |
| lodash   | the **positive** sink (`lodash.merge`)                |
| js-yaml  | the **negative** sink (`js-yaml.load`), never proven  |

## Ground-truth taint per route

| route         | handler       | source     | sink          | verdict        | why |
| ------------- | ------------- | ---------- | ------------- | -------------- | --- |
| `POST /merge` | `handleMerge` | `req.body` | `lodash.merge`| **tainted**    | `req.body` is passed to the cross-file helper `settings.applyDefaults`, whose parameter flows straight into `lodash.merge`. Proven path: `ep -> handleMerge -> settings.applyDefaults -> lodash`. |
| `POST /parse` | `handleParse` | —          | `js-yaml.load`| `not_proven`   | `req.body` is read but overwritten by a constant on a straight-line path (last-write-wins KILL) before `yaml.load`. |
| `GET /static` | `handleStatic`| —          | `js-yaml.load`| `not_proven`   | `yaml.load` is called with a constant literal only. |
| `GET /echo`   | `handleEcho`  | `req.query`| —             | `not_proven`   | A request source is read but never passed to a dependency call. |

## Dependency-level verdict (what `compute_taint` returns, keyed by dep)

`compute_taint` aggregates across every entry point: a dependency is `tainted`
if ANY reaching path proves a flow, else `not_proven`.

| dependency        | verdict      | evidence                                              |
| ----------------- | ------------ | ----------------------------------------------------- |
| `dep:npm:lodash`  | **tainted**  | source `req.body`, sink `lodash.merge`, via `/merge`  |
| `dep:npm:js-yaml` | `not_proven` | reached by `/parse` and `/static`, neither proves a flow |

(`GET /echo` reaches no dependency, so it contributes nothing.)
