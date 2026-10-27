# go-taint-app — Go taint fixture

A minimal Go web app (gin + net/http) whose routes are hand-verified for the
sound Go taint pass (`scanner/taint/go.py`). The taint pass asks one question
and only answers it when fully proven:

> Does attacker-controlled request input at a route handler flow, hop by hop,
> into a call that lands in a vulnerable Go module?

The cardinal rule: a MISSED flow is acceptable; a FALSE `tainted` is a critical
failure. Everything defaults to `not_proven` (never "safe"). Everything is
offline: the `dep:Go:*` nodes, the `calls` edges and the resolved symbols all
come from the analyzer with no `go mod download`.

## Dependencies

| module                        | why it is here                                       |
| ----------------------------- | ---------------------------------------------------- |
| github.com/gin-gonic/gin      | the web framework (route + request sources)          |
| gopkg.in/yaml.v2              | the **positive** sink (`yaml.Unmarshal`)             |
| github.com/BurntSushi/toml    | the **negative** sink (`toml.Unmarshal`), never proven |

## Ground-truth taint per route

| route           | handler          | source        | sink             | verdict      | why |
| --------------- | ---------------- | ------------- | ---------------- | ------------ | --- |
| `POST /import`  | `importHandler`  | `c.PostForm`  | `yaml.Unmarshal` | **tainted**  | `c.PostForm("data")` is passed to the helper `parseYAML`, whose parameter flows (via `[]byte(...)`) straight into `yaml.Unmarshal`. Proven path: `ep -> importHandler -> parseYAML -> yaml`. |
| `POST /safe`    | `safeHandler`    | —             | `toml.Unmarshal` | `not_proven` | `c.PostForm` is read but overwritten by a constant on a straight-line path (last-write-wins KILL) before `parseTOML`. |
| `POST /static`  | `staticHandler`  | —             | `toml.Unmarshal` | `not_proven` | `parseTOML` is called with a constant literal only. |
| `GET /echo`     | `echoHandler`    | `r.FormValue` | —                | `not_proven` | A net/http request source is read but never passed to a dependency call. |

## Dependency-level verdict (what `compute_taint` returns, keyed by dep)

`compute_taint` aggregates across every entry point: a dependency is `tainted`
if ANY reaching path proves a flow, else `not_proven`.

| dependency                            | verdict      | evidence                                                   |
| ------------------------------------- | ------------ | ---------------------------------------------------------- |
| `dep:Go:gopkg.in/yaml.v2`             | **tainted**  | source `c.PostForm`, sink `yaml.Unmarshal`, via `/import`  |
| `dep:Go:github.com/BurntSushi/toml`   | `not_proven` | reached by `/safe` and `/static`, neither proves a flow    |

(`GET /echo` reaches no dependency, so it contributes nothing.)
