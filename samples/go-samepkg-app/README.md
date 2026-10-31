# go-samepkg-app

A single-package Gin app spread across **multiple files in one directory**
(`package main` in `main.go`, `handler.go`, `parse.go`). It is the fixture for
the Go analyzer's **sound same-package cross-file** call/handler resolution.

In Go a package is a directory, so a top-level function declared in one file is
callable as a **bare name** (no import, no qualifier) from any other file of the
same directory. This fixture wires attacker input through exactly such bare
cross-file references:

```
main.go     r.POST("/import", importHandler)      bare handler, declared in handler.go
handler.go  importHandler: data := c.PostForm(..) ; parseConfig(data)   bare call -> parse.go
parse.go    parseConfig(data): yaml.Unmarshal([]byte(data), &cfg)       external dep sink
```

## Ground truth

The chain `POST /import -> importHandler -> parseConfig -> yaml.Unmarshal`
crosses two file boundaries within the same package, using only bare names.

- **Reachability:** `gopkg.in/yaml.v2` is **reachable** — the route reaches it
  only through the bare same-package `route_to_handler` + `calls` edges
  (`ep:POST:/import -> fn:handler.go:importHandler -> fn:parse.go:parseConfig ->
  dep:Go:gopkg.in/yaml.v2`).
- **Taint:** `gopkg.in/yaml.v2` is **tainted** — attacker-controlled
  `c.PostForm` flows cross-file into `yaml.Unmarshal`. Source `c.PostForm`, sink
  `yaml.Unmarshal`, entrypoint `POST /import`, with a path spanning the multiple
  files.

Everything is offline and deterministic: the dependency nodes, the resolved
bare cross-file edges, and the taint flow all come from the static analyzer with
no network and no `go mod download`.
