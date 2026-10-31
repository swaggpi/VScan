# go-mux-app — gorilla/mux route + taint fixture

A minimal Go web app using `github.com/gorilla/mux` whose single route is
hand-verified for the Go analyzer's route detection and the sound taint pass.
Everything is offline: the `dep:Go:*` nodes, `calls` edges and resolved symbols
all come from the analyzer with no `go mod download`.

## Why mux is interesting

gorilla/mux registers routes with `r.HandleFunc(path, handler)` — the same
method name net/http uses — and pins the HTTP verb with an optionally chained
`.Methods("GET", "POST", ...)`. The analyzer treats a `HandleFunc` call as a
route only when its receiver is a recognised mux router (bound from
`mux.NewRouter()`) or the stdlib net/http, so a `.HandleFunc` on any other
receiver is NOT a route.

## Dependencies

| module                    | why it is here                               |
| ------------------------- | -------------------------------------------- |
| github.com/gorilla/mux    | the web framework (route source)             |
| gopkg.in/yaml.v2          | the **positive** sink (`yaml.Unmarshal`)     |

## Ground-truth route detection

| route          | framework | how detected                                                        |
| -------------- | --------- | ------------------------------------------------------------------- |
| `POST /import` | `mux`     | `r.HandleFunc("/import", importHandler).Methods("POST")` — the chained `.Methods("POST")` pins the verb, so the entrypoint is `ep:POST:/import` (not `ANY`). The handler `importHandler` resolves in-file. |

A `HandleFunc` with **no** `.Methods(...)` would instead emit `ep:ANY:/path`
(mux matches all methods by default).

## Ground-truth taint

| route          | handler         | source        | sink             | verdict     | why |
| -------------- | --------------- | ------------- | ---------------- | ----------- | --- |
| `POST /import` | `importHandler` | `r.FormValue` | `yaml.Unmarshal` | **tainted** | `r.FormValue("data")` is passed to `parseYAML`, whose parameter flows (via `[]byte(...)`) straight into `yaml.Unmarshal`. Proven path: `ep:POST:/import -> importHandler -> parseYAML -> yaml`. |

## Dependency-level verdict (what `compute_taint` returns)

| dependency                 | verdict     | evidence                                                  |
| -------------------------- | ----------- | --------------------------------------------------------- |
| `dep:Go:gopkg.in/yaml.v2`  | **tainted** | source `r.FormValue`, sink `yaml.Unmarshal`, via `/import` |
