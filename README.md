# VScan

A dependency vulnerability scanner that checks whether a CVE is actually **reachable** from your public entry points — instead of listing every CVE in your dependency tree.

## How it works

1. Builds a call graph from source with tree-sitter (Python, JavaScript, PHP, Go).
2. Traces, from each public entry point, which dependencies are reachable and whether the vulnerable function is actually called.
3. Runs taint analysis to check whether attacker-controlled input reaches the vulnerable call.
4. Correlates dependencies against OSV, plus CISA KEV and EPSS.

Every finding gets one verdict:

| Verdict | Meaning |
| --- | --- |
| `not reached` | The CVE exists, but no entry point reaches the package. |
| `reachable` | The vulnerable code is reachable, but attacker input isn't proven to get there. |
| `exploitable` | Attacker input provably reaches the vulnerable call. |

Reachability is a **lower bound**: VScan only follows call edges it can resolve, so `not reached` is conservative (a missed path is possible; a false "exploitable" is not).

## Install

```sh
pip install .
```

## Use

CLI:

```sh
vscan audit path/to/repo                       # ranked, reachability-aware findings
vscan audit path/to/repo --json out.json       # machine-readable
vscan audit path/to/repo --sarif out.sarif     # for GitHub code scanning
vscan audit path/to/repo --markdown out.md      # a PR-comment summary
vscan audit path/to/repo --fail-on reachable   # exit non-zero to gate CI
```

GitHub Action — on every PR it posts a reachability-aware comment and uploads SARIF to code scanning:

```yaml
- uses: swaggpi/VScan@main
  with:
    path: .
    fail-on: reachable
```

MCP server — exposes the scan as tools for an AI agent (scan overview, find, describe, call graph, trace entrypoint, dependency reachers, audit, finding detail):

```sh
vscan-mcp            # stdio; or --transport http for a remote server
```

## AI layer (optional, advisory)

With an OpenAI-compatible model configured, VScan adds advisory overlays. They **never change a deterministic verdict** — they are shown separately and labelled as inferred/unverified:

- **Exposure** — whether an endpoint is public or internal, read from the repo's docs.
- **Inferred edges** — fills dynamic-dispatch gaps static analysis can't resolve, surfacing dependencies as *likely* reachable.
- **Attack surface** — flags candidate code-level issues (SSTI, injection, path traversal, …) on public endpoints as unverified hypotheses.
- **Chat** — ask questions about a scan in natural language.

Configure via environment (no model → VScan runs fully on the deterministic analysis):

```sh
LLM_BASE_URL=...   # OpenAI-compatible endpoint
LLM_API_KEY=...
LLM_MODEL=...
```

The web backend (`vscan-web`) serves these under `/api/*` for the dashboard.

## Dashboard

`dashboard/` is a static viewer for a scan bundle:

```sh
vscan audit path/to/repo --bundle bundle.json
```

Open it from a web server (it loads the bundle and, if the backend is running, the AI overlays).
