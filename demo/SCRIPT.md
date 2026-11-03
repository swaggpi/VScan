# VScan — 3-minute demo script

Target: **2:58**. Hard limit 3:00. ~430 words at ~150 wpm.

Read the voiceover from `demo/teleprompter.html` (open it in a browser, press
Space to start). Every number below is from a real run on `samples/acme-api`;
re-run before recording so what is on screen matches what is said.

## Setup before recording

```sh
cd .claude/worktrees/scanner-layer1
VSCAN_DEMO_REPOS="$PWD/samples/acme-api,$PWD/samples/plugin-reports" vscan-web   # :8000
python3 demo/serve.py                                                            # :8080, proxies /api
```

Wait for `curl localhost:8080/api/health` to report `"status":"ready"` **and**
`/api/attack-surface` to stop returning 503 — the AI overlays warm for ~2 min
after startup. Record at 1600×900.

Terminal: large font, dark background, nothing but the prompt.

---

## Beat 1 — The problem (0:00 – 0:14)

**Screen:** terminal. Run a plain `pip-audit`-style list, or scroll the raw
`vscan audit samples/acme-api` findings fast so the wall of CVEs flies past.

> Here's the dependency scan for a small Flask service. A hundred and
> forty-five known CVEs. Every one of them is real. And almost none of them
> matter, because nothing in this codebase ever calls the vulnerable code.
> That's the job: finding the one that does.

## Beat 2 — The scan (0:14 – 0:40)

**Screen:** `vscan audit samples/acme-api` — let it run live, it takes ~14s.
Land on the Summary + Funnel lines.

> VScan builds a call graph of the repo with tree-sitter, traces every public
> route into your dependencies, and then runs taint analysis to see whether
> attacker-controlled input actually reaches the vulnerable call.
> Nineteen dependencies. A hundred and forty-five CVEs. Sixteen reachable.
> Four where we confirmed the vulnerable function is really called. And one
> that is genuinely exploitable.

## Beat 3 — The graph, staged (0:40 – 1:36)

**Screen:** `http://localhost:8080/index.html?demo=1`. Advance with → on each
cue below.

**Stage 0 — graph only (0:40 – 0:55)**

> This is the whole attack surface. Public entry points on the left, your
> functions in the middle, dependencies on the right. Grey means a package has
> a CVE that nothing reaches.

**Stage 1 — press → , left panel (0:55 – 1:08)**

> Ten public routes do reach a vulnerable package. These are the ones worth
> your afternoon — everything else is noise.

**Stage 2 — press → , right drawer + highlighted path (1:08 – 1:25)**

> Here's the one that matters. `POST /documents/import` takes the request body,
> hands it through two service layers into a config loader, and calls
> `yaml.full_load` on it — PyYAML 5.3.1, CVE-2020-14343, arbitrary code
> execution. That chain is the proof: attacker input to vulnerable call,
> rendered straight from the call graph.

> **Note:** once the AI layer has warmed, the drawer's top card is the *AI
> pen-tester hypothesis*, labelled unverified — not the deterministic verdict.
> So don't say "that's not a guess" here; the proof you're pointing at is the
> highlighted chain in the graph and the `EXPLOITABLE` badge in the left rail.
> Beat 4 picks that card up deliberately.

**Stage 3 — press → , funnel bar (1:25 – 1:36)**

> A conventional scanner hands you a hundred and forty-five alerts. VScan
> proves one is exploitable. That's a ninety-nine percent cut in what you have
> to read.

## Beat 4 — Muse (1:36 – 2:21)

**Screen:** hold on the drawer's AI card for the first two lines, then cut to a
`likely_unaffected` triage entry in the terminal output (`requests` /
CVE-2024-35195), then to `chat.html`.

> That red card is an AI pen-tester's hypothesis — labelled unverified, and
> here it independently lands on the same call. It's one of four layers running
> on Meta's Muse Spark Open.
> Muse triages every reachable CVE at symbol level — here it clears `requests`
> CVE-2024-35195, because the project only calls `requests.post`, never a
> `Session`, and Session pooling is what that CVE needs.
> It also reads your docs to judge which routes are internet-facing, and
> proposes call edges static analysis can't resolve.
> And you can just ask it.

**Screen:** chat — send "What's actually exploitable in this project?"
**Cut here.** The answer takes ~65 seconds; jump-cut to the rendered reply and
let the tool-call list show under it.

> Muse answers by calling VScan's own tools over MCP, and it shows you every
> call it made. Nothing it says can change a verdict — the model advises, the
> static analysis decides.

## Beat 5 — Shipping it (2:18 – 2:42)

**Screen:** the generated PR comment markdown, then the SARIF in GitHub code
scanning, then `--fail-on`.

> It runs where you work. A GitHub Action posts the reachability-aware comment
> on every pull request, uploads SARIF to code scanning, and
> `--fail-on reachable` gates CI — so you block the build on an exploitable
> path, not on a CVE count.

## Beat 6 — Close (2:42 – 2:58)

**Screen:** repo README, then the funnel one more time.

> Everything here was built during the hackathon: the call-graph scanner, the
> taint engine, the four Muse layers, the MCP server, the Action and this
> dashboard. It's open source and it runs on your laptop.
> One hundred and forty-five alerts in. One that matters out.

---

## Capturing it

Record at 1600×900 so the dashboard matches what the script was timed against.
Put the teleprompter on a second screen (or a phone) — not in the captured area.

Screen + mic in one pass, with ffmpeg:

```sh
ffmpeg -video_size 1600x900 -framerate 30 -f x11grab -i :0.0+0,0 \
       -f pulse -i default \
       -c:v libx264 -preset veryfast -crf 18 -pix_fmt yuv420p \
       -c:a aac -b:a 192k demo-take.mp4
```

Adjust `+0,0` to the window's top-left corner. If the voiceover is recorded
separately, drop the `-f pulse -i default` and `-c:a`/`-b:a` pair and mux the
audio afterwards.

Record Beat 4's chat answer as its own take (see the latency note below) and
cut the two together.

## Recording notes

- The 66s chat latency is the one thing that cannot be shown in real time.
  Record it as its own take and jump-cut; don't speed-ramp the typing, it looks
  fake.
- `/api/attack-surface` returns 503 while the AI layer warms. If the legend's
  AI states are missing from the graph, you started recording too early.
- `vscan audit` is ~14s warm, ~50s cold — OSV results cache for 7 days, so do a
  throwaway run first.
- Don't show `.env`. The Baseten key is in it.
