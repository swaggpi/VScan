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

## Progress log (overnight)
- DONE: A1/A2/A3 research (notes in .research/). B reachability engine (committed:
  `vulnreach reachability`, 77 tests). 
- IN PROGRESS: C correlator (OSV+KEV+EPSS + `audit` + reachability join);
  E3a Python registry routes (Flask-RESTful add_resource -> fixes redash 0-entrypoints,
  add_url_rule/add_api_route, blueprint/APIRouter prefix composition).

## Research-driven decisions (from A1 — apply in remaining work)
- **Three-way reachability verdict** (A1 top [S]): reachable / potentially_reachable
  (a path exists but crosses >=1 unresolved/unknown edge) / unreachable (ONLY when every
  path is fully resolved with zero unknown edges). Upgrade `reachability.py` to this after
  C lands (keep API additive so C's join doesn't break). This is the honest model every
  mature tool (Endor/Socket/GitLab/govulncheck) uses.
- **Edge/verdict provenance**: mark how each edge/verdict was derived (resolved_static vs
  unknown+reason). Downstream (report, agent) keys off this.
- **LLM scope (agent layer D)**: the LLM may ONLY look at `unknown`/unresolved edges and
  may ONLY promote unknown -> potentially_reachable, or summarize exposure from docs. It
  must NEVER produce a confident reachable verdict or silently add a `calls` edge. Keep its
  output in a separate provenance tier. (A1: LLM4PFA/SEA support post-hoc unknown-resolution.)
- **Symbol-level matching** (correlator): prefer matching the advisory's affected symbol,
  not just package==vulnerable. (Refinement; package-level is the baseline.)
- **Don't chase points-to** — name-resolution + light over-approx is the hackathon sweet
  spot; biggest JS/Go/PHP gain is cross-file import resolution (E2, L-effort, optional).
- **Don't over-claim transitive-dep reachability** (Semgrep's caution); be honest in copy.
- **Coverage/confidence report**: files parsed vs failed, % call sites resolved, count+reasons
  for unknown. Add to the overview output (F) — it is part of an "in-depth overview".

## Mandate update (user, overnight)
Run until told to stop. After the core (C correlator, D agent layer, three-way
reachability, F integration+overview+report) is DONE and SOLID, take on the
stretch items previously deferred, each sound + tested + reviewed:
- E2a JS cross-file call resolution (build a repo-wide JS function/export index;
  resolve imports of local modules to real functions). Must not add false edges.
- E2b Go cross-file call resolution (package-level symbol index).
- E-prov edge/verdict provenance tiers (resolved_static / overapprox / unknown+reason).
- E-pycg deeper Python resolution (PyCG-style assignment graph) where it buys recall.
- More framework route coverage (A3 Tier-2/3: DRF routers, Laravel/Gin groups, etc.)
Order by value×safety; stop any item that cannot be made sound and move on.
Non-negotiable: never fabricate an edge/verdict to look more complete.
