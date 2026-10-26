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

## License

MIT
