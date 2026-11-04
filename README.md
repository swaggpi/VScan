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

## Example

`vscan audit samples/acme-api` on the bundled sample service:

```
Funnel: 19 deps · 145 known CVEs · 16 reachable · 1 vulnerable-function confirmed · 1 exploitable

 6. PyYAML 5.3.1 [PyPI] -- CVE-2020-14343
    severity: CRITICAL   EPSS 0.060
    REACHABLE via GET /admin/config, POST /documents/import
    taint: request.get_data -> yaml.full_load
    [ep:POST:/documents/import -> fn:api/documents.py:import_document
     -> fn:services/document_service.py:ingest -> fn:core/config_loader.py:parse_yaml
     -> dep:PyPI:PyYAML]
```

The other 144 findings are real CVEs that no entry point reaches, or whose vulnerable function the project never calls.

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

Built and tested against **Meta Muse Spark Open** (`meta-models/muse-spark-open-1026`), served by Baseten. The client is a plain OpenAI-compatible chat-completions caller, so any such endpoint works.

With a model configured, VScan adds advisory overlays. They **never change a deterministic verdict** — they are shown separately and labelled as inferred/unverified:

- **Triage** — for each reachable CVE, compares the symbols the project actually calls against what the CVE says is vulnerable. `likely_unaffected` is gated hard: it requires the CVE to name a specific vulnerable function, that function to be absent from the called-symbol set, and no unresolved calls into the dependency. Anything else is `uncertain`. The gate is enforced on the model's output, so the model cannot talk VScan into a false "safe".
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

## Provenance

Built for the Meta Global AI Developer Hackathon. The repository starts from an empty commit on 2026-10-26 (kickoff day) and every part of it was written during the event: the scanner and the Python/JavaScript/PHP/Go analyzers, the reachability and taint engines, the OSV/KEV/EPSS correlator, the four Muse advisory layers, the MCP server, the GitHub Action and the dashboard. `git log` is the full record.

## Limitations

- Reachability is a lower bound — see above. On the sample service, 68% of call sites resolve; the rest are reported as unresolved, never guessed.
- PHP and Go dependency reachability is single-file for PHP; Go resolves across packages within one module.
- OSV matching needs exact pinned versions. Unpinned dependencies are reported as skipped, not as clean.
- The AI layers are advisory and can be wrong. They are labelled as such everywhere they appear, and they cannot change a verdict.

## Demo

`demo/demo.mp4` — a 2:56 walkthrough: the scan, the proven attack path, the
four Muse layers, the MCP chat, and the GitHub Action. `demo/SCRIPT.md` is the
narration, and `demo/teleprompter.html` is the tool it was read from.

## Self-scan

VScan runs against its own repository on every pull request and on pushes to
`main` (`.github/workflows/vscan.yml`, consuming the action with `uses: ./`).
It uploads SARIF to code scanning and posts the funnel as a PR comment.

Note what that scan covers: the repo bundles deliberately vulnerable fixture
apps under `samples/`, and the reachable findings it reports come from those,
not from VScan's own dependencies. The gate is set to `fail-on: tainted`, so
CI blocks on a proven attacker-input-to-vulnerable-call path rather than on a
CVE count.
