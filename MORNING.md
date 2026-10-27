# Morning report

Status as of the overnight run. **Everything below is committed on branch
`worktree-scanner-layer1` and passing — but NOT pushed** (see "Action needed").

## TL;DR
The full pipeline works end to end and is live-verified. `vulnreach audit <repo>`
scans a repo, builds a 4-language knowledge graph, computes three-way reachability
(which entry point reaches which functions and dependencies), correlates the deps
against real CVE data (OSV + CISA KEV + EPSS), reports coverage/confidence, and —
with `--explain` — runs an agent pass over the docs to assess exposure. The
dashboard overlays the reachable-vulnerable findings on the graph. **422 tests pass**,
across three adversarial review rounds (all findings fixed).

## Action needed from you (2 things)
1. **Push the branch** — 17 commits are local-only because the overnight push was
   auto-blocked. From the repo root:
   `git push origin worktree-scanner-layer1`
   (If this worktree is gone, the branch still exists in the main checkout.)
   That updates PR #1 (https://github.com/swaggpi/vulnreach/pull/1), which
   currently shows only the first-night work (scanner + analyzers + viewer).
2. **Activate the real agent model** (optional; offline heuristic works without it):
   claim your API credits, then set `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`.
   Then `vulnreach audit <repo> --explain` uses the model (else an offline heuristic).
   The branded "built with ..." section still needs adding to the README (left as a
   placeholder) — do that last, before submission, since the repo is public.

## Demo it
```
cd <repo>/.claude/worktrees/scanner-layer1   # or wherever the branch is checked out
./.venv/bin/vulnreach scan          samples/vulnerable-app
./.venv/bin/vulnreach reachability  samples/vulnerable-app
./.venv/bin/vulnreach audit         samples/vulnerable-app            # live: real CVEs
./.venv/bin/vulnreach audit         samples/vulnerable-app --explain  # + docs exposure
```
Live `audit` on the sample surfaces e.g. **PyYAML 3.13 -> CVE-2020-14343 (arbitrary
code execution), REACHABLE via POST /import** with the exact call path, while
unreachable vulns are flagged as such. The `dashboard/index.html` viewer shows the
reachability trace (open it in a browser, click POST /import).

Real-repo corpus to demo against: `scripts/fetch_test_corpus.sh` (gitignored
`test-corpus/`). redash now yields **121 entry points** (Flask-RESTful routes).

## What got built overnight
- Reachability engine (`vulnreach reachability`) — endpoint -> functions -> deps,
  three-way verdict (reachable / potentially_reachable / unreachable) with a sound
  rule (unreachable only when the reachable region is fully resolved).
- Correlator (`vulnreach audit`) — OSV batch + CISA KEV + EPSS (+ optional NVD),
  ranked KEV -> EPSS -> reachable -> severity, reachability join. Network-isolated,
  offline-safe.
- Agent layer (`--explain`) — docs-based exposure assessment, provider-neutral,
  advisory-only (never changes a verdict), offline heuristic fallback.
- Registry-style Python routes (Flask-RESTful add_resource, add_url_rule,
  add_api_route, prefix composition) — redash 0 -> 121 entry points.
- JavaScript cross-file resolution — handlers/calls across modules now connect
  (express-es6: 0 -> 5 route_to_handler edges).
- Go cross-package resolution — calls/handlers across packages connect (sound,
  single-module only).
- Dashboard vulnerability overlay — `audit --bundle` feeds the viewer; vulnerable
  deps get a severity ring, reachable-and-vulnerable deps are the top signal, and
  a findings panel ranks the CVEs. Live sample bundle ships for instant demo.
- Coverage / confidence report — files parsed, call-site resolution rate, verdict
  breakdown, and an honest lower-bound note (in `scan`, `audit`, and the bundle).
- Performance — OSV vuln lookups are cached (7-day disk cache) and fetched in
  parallel: a 61-dep repo went ~50s cold -> ~2s warm, so demo re-runs are instant.
- Three adversarial review rounds (initial analyzers, full core, cross-file); every
  confirmed finding fixed — notably an unsound-"unreachable" verdict, a correlator
  wrong-dependency-attribution bug, and a JS cross-file symbol-table leak.
- Full README rewrite; a reachability dashboard.
- Research notes in `.research/` (gitignored). Two adversarial review rounds; all
  confirmed findings fixed (notably an unsound-"unreachable" blocker and a
  correlator wrong-dependency-attribution bug).

## Shipped since
- `symbol_match` — deterministic 3-tier signal per finding (`confirmed` /
  `package_reachable` / `no_path`), derived from the reachability verdict.
- Python taint pass — `tainted` when web input (Flask/FastAPI/Django) provably
  reaches the vulnerable call, else `not_proven`; gated by the advisory's sink.
- `audit` outputs for CI: `--sarif`, `--markdown`, `--fail-on` exit codes, and
  the one-line impact funnel (deps · CVEs · reachable · confirmed · exploitable).
- GitHub Action — composite action: SARIF upload, PR comment, `fail-on` gate.
- Dashboard — impact funnel plus `symbol_match` / taint escalation view; bundles
  refreshed.

## Honest limitations (documented, not hidden)
- The cardinal rule holds throughout: an edge/verdict is asserted only when soundly
  resolved; unknowns are recorded, never guessed. Reachability is a lower bound.
- PHP and Go are still single-file (Go cross-file is the next stretch item, in
  progress); PHP emits no dependency call edges (namespace->package is unsound).
- OSV needs exact pinned versions; unpinned deps are reported as skipped, not clean.
- The offline exposure heuristic is crude (keyword-based); the real model is sharper.

## Where things are
- Branch `worktree-scanner-layer1`, 422 tests passing.
- `PLAN.md` has the full overnight plan, decisions, and remaining backlog.
- PHP is still single-file (JS and Go have cross-file; PHP cross-file was judged
  low-value/high-risk given its dynamic autoloading, and left out rather than done
  unsoundly).
