# Overnight build plan

**Mission:** make the analyzers bulletproof and get a full scan working end to
end, so that by morning a single scan of a repo produces an in-depth overview:
a complete knowledge/dependency graph, per-endpoint reachability (which endpoint
reaches which functions and which dependencies), known-vulnerability correlation
on those dependencies, and an agent pass that reads the docs to assess exposure.

**This file is the durable state.** Fresh agents and post-compaction context
reconstruct from here + `git log`. Keep it updated as tasks complete.

## Morning deliverable (what must demo)
Run `vulnreach scan <repo>` (+ a report command) and get:
1. Knowledge + dependency graph (all 4 languages) — DONE in layer 1.
2. **Per-endpoint reachability**: for each public entry point, the functions it
   reaches and the dependencies those reach. (endpoint -> functions -> deps)
3. **Known-vulnerability correlation**: dependencies matched against public CVE
   data (OSV primary; enrich with CISA KEV + EPSS). No API key needed.
4. The money output: **which endpoints can reach a known-vulnerable dependency.**
5. **Agent pass over docs**: reads doc nodes + the reachability graph to judge
   exposure (is the route public/unauth?) and summarize. Offline fallback now;
   real Meta Muse calls behind `META_API_KEY` (user claims credits in the AM).

## Hard constraints (do NOT violate)
- **Cardinal rule:** never emit a call/route/import/reachability edge that isn't
  soundly resolved. Record unresolved; never fabricate. False reachability is
  the worst possible bug and the whole project's credibility rests on it.
- No network in the scanner/analyzers. Network only in the correlator (OSV/NVD/
  KEV/EPSS) and the agent layer (Meta API), both clearly isolated.
- No secrets in the repo. Meta/OSV keys from env only. No "Meta/hackathon/Muse/
  Llama" strings anywhere in committed code/docs (goes in README at the very end).
- Completion gate before every commit (placeholders, duplicates, test integrity,
  verification actually exercises new code, plan drift, no artifacts).
- Don't weaken/skip tests to pass. Don't push to main or merge. Commit+push to
  the branch incrementally so work survives.

## Current state (start of overnight)
- Branch `worktree-scanner-layer1`, PR #1 (unmerged). 67 tests pass.
- Scanner (layer 1) done: graph core, walker, manifests (py/js deep, php/go thin),
  analyzers (python deep cross-file; js/php/go single-file, tree-sitter), docs
  ingestion, CLI, reachability viewer in `dashboard/`.
- Analyzers hardened once already (two false-edge review rounds fixed).

## Task list (granular; check off as done, commit each)
### A. Research (informs everything; read-only)
- [ ] A1 Reachability-based SCA + call-graph/points-to techniques; how CodeQL,
      Semgrep, Endor Labs, Socket, OSV-Scanner do reachability. What makes an
      analyzer robust; what we're missing. -> notes in `docs/research/`.
- [ ] A2 Exact API contracts: OSV.dev batch, NVD, CISA KEV catalog, EPSS; and the
      Meta Model API request format (OpenAI-compatible? model id). -> notes.
- [ ] A3 Framework route-detection patterns incl. REGISTRY styles (Flask-RESTful
      add_resource, DRF routers, Django include(), Blueprint, Express Router
      mounts, Laravel route groups). redash currently yields 0 entrypoints -> fix.

### B. Reachability engine (no key needed)
- [ ] B1 `scanner/reachability.py`: from the graph, compute per-entrypoint the
      reachable functions and reachable dependencies (BFS over route_to_handler +
      calls), with the path. Tests on the sample apps.
- [ ] B2 CLI: `vulnreach reachability <repo>` (or `scan --reachability`) emitting
      the endpoint -> functions -> deps report (text + JSON).

### C. Correlator (network, isolated; no key needed)
- [ ] C1 `scanner/correlate/` OSV batch client: deps -> vulns. Offline-safe
      (skip gracefully if no network). Tests with recorded fixtures.
- [ ] C2 Enrich: CISA KEV (actively-exploited flag) + EPSS (exploit probability).
- [ ] C3 Join reachability x correlation: per endpoint, the reachable vulnerable
      deps, ranked by KEV+EPSS. This is the headline output.

### D. Agent layer (docs) — real-API-ready, offline fallback now
- [ ] D1 `scanner/agent/` client interface (MetaMuseClient) OpenAI-compatible,
      key from env; deterministic offline fallback when no key.
- [ ] D2 Doc+graph exposure assessment: per reachable-vulnerable finding, read
      doc nodes + route context, judge public/unauth exposure, summarize.

### E. Hardening (bulletproof)
- [ ] E1 Adversarial test corpus expansion per A1/A3 findings; fix any false
      edges / crashes found running all analyzers over the 6 corpus repos + more.
- [ ] E2 Cross-file call resolution for JS/Go where sound (research-gated).
- [ ] E3 Registry-route detection (A3) so redash etc. yield entrypoints.
- [ ] E4 Fresh adversarial review of the whole pipeline; fix confirmed findings.

### F. Integration + overview
- [ ] F1 One flow/command producing the full overview (graph + reachability +
      vulns + agent assessment). Demo on sample + >=2 corpus repos.
- [ ] F2 Update viewer to show reachable-vulnerable paths if time allows.
- [ ] F3 Morning report in this file: done / blocked / how to demo.

## Decisions / notes log
- Priority if time runs short: B (reachability) > C (correlation) > E3 (registry
  routes) > D (agent) > E2 (cross-file) > F2. B+C+E3 are the demo core.
- Meta API: build to OpenAI-compatible chat completions; confirm exact endpoint/
  model in A2. Cannot test real calls (no key) — mock-verify + leave activation.
- Keep each layer behind a clean seam; scanner stays network-free.
