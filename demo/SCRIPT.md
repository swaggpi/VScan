# VScan — 3-minute demo script

**2:51.** 355 words at ~125 wpm — paced to be read aloud comfortably, with the
emphasis lines (PyYAML, "genuinely exploitable") deliberately slow.

`demo/teleprompter.html` is the source of truth for wording and timing; this
file is generated from it. Open the teleprompter in a browser and press Space
to run it, or read along with `demo-karaoke.mp4`, which has the same lines
burned in.

The recorded clips line up with these segment boundaries:
`seg0 0:00–0:14 (intro card) · seg1 0:14–0:48 · seg2 0:48–1:43 · seg3 1:43–2:01 · seg7 2:01–2:14 (Plugin Reports) · seg4 2:14–2:28 (chat) · seg5 2:28–2:38 · seg6 2:38–2:51`

## Setup before recording

```sh
cd .claude/worktrees/scanner-layer1
VSCAN_DEMO_REPOS="$PWD/samples/acme-api,$PWD/samples/plugin-reports" vscan-web   # :8000
python3 demo/serve.py                                                            # :8080, proxies /api
```

Wait for `curl localhost:8080/api/health` to report `"status":"ready"` **and**
`/api/attack-surface` to stop returning 503 — the AI overlays warm for ~2 min
after startup. Record at 1600x900.

The two figures on the intro card are attributed on screen (FIRST's 2026
forecast; VulnCheck). Published 2026 CVE counts vary by source and date — the
card cites only those two and rounds nothing.

---

## Beat 0 · why now  (0:00 – 0:14)

**0:00 — CARD · the AI-CVE surge**

> Sixty-six thousand CVEs this year — about double last year.

> AI finds them faster than anyone can triage.

> But volume isn't risk. Which one actually reaches your code?


## Beat 1 · the noise  (0:14 – 0:20)

**0:14 — TERMINAL · scroll the CVE wall**

> Here's one small Flask service. A hundred and forty-five known CVEs.


## Beat 2 · the scan  (0:20 – 0:48)

**0:20 — RUN · vscan audit samples/acme-api**

> VScan builds a call graph with tree-sitter, and traces every public route into your dependencies,

> then runs taint analysis to see whether attacker input reaches the vulnerable call.

**0:33 — LAND ON · the Funnel line**

> Nineteen dependencies. A hundred and forty-five known CVEs. Sixteen of them reachable.

> And exactly one of them turns out to be genuinely exploitable.

> Sixty-eight percent of call sites resolve, never guessed.


## Beat 3 · the graph  (0:48 – 1:32)

**0:48 — SWITCH · dashboard ?demo=1 (stage 0)**

> This is the whole attack surface: public entry points on the left, your functions, dependencies on the right.

**0:56 — PRESS → · left panel in**

> Ten of those public routes reach a vulnerable package.

> These are the ones worth your afternoon.

**1:03 — PRESS → · drawer + path**

> Here's the one that matters. POST /documents/import takes the request body,

> hands it down two service layers, and calls yaml.full_load on it.

> That's PyYAML 5.3.1, CVE-2020-14343 — arbitrary code execution.

> That chain is the proof — attacker input to vulnerable call, straight from the call graph.

**1:25 — PRESS → · funnel bar in**

> A conventional scanner hands you a hundred and forty-five alerts. VScan proves one.


## Beat 4 · Muse  (1:32 – 2:28)

**1:32 — HOLD · the drawer's AI card**

> That red card is an AI pen-tester's hypothesis — unverified, and it lands on the same call.

> One of four layers on Meta's Muse Spark Open.

**1:43 — SWITCH · triage output in terminal**

> Muse triages every reachable CVE — here it clears requests CVE-2024-35195,

> because the project only ever calls requests.post, and never reuses a pooled Session.

> Only when the CVE names a function you never call.

**2:01 — SWITCH · Plugin Reports scan**

> On a second project, it reads the docs to judge exposure.

> And where static analysis hits dynamic dispatch, Muse proposes the edges it can't resolve. Likely, never proven.

**2:14 — SWITCH · chat.html, send the question**

> And you can just ask it.

**2:17 — CUT · jump to the rendered answer**

> Muse answers by calling VScan's own tools over MCP, showing every call.

> Nothing it says changes a verdict. The model only advises.


## Beat 5 · shipping it  (2:28 – 2:38)

**2:28 — SWITCH · PR comment**

> A GitHub Action posts this comment on every pull request,

> uploads SARIF to code scanning, and gates CI on exploitable paths.


## Beat 6 · close  (2:38 – 2:51)

**2:38 — SWITCH · README**

> All of this was built during the hackathon — scanner, taint engine, Muse layers, MCP server, dashboard.

**2:46 — SWITCH · the funnel, hold**

> A hundred and forty-five alerts in. One that matters out.


---

## Recording the voiceover

Play `demo-karaoke.mp4` and read the lines as they highlight; the clock in the
corner keeps you honest. Record the audio separately, then mux:

```sh
arecord -D plughw:5,0 -f cd -c 1 voice.wav     # pick your mic with `arecord -l`
ffmpeg -i demo-clean.mp4 -i voice.wav -c:v copy -c:a aac -b:a 192k -shortest final.mp4
```

Check sync at the three context switches: 0:14 (card to terminal), 1:43
(dashboard to triage), 2:14 (plugin to chat).

## Notes

- The chat answer takes ~70s in reality. The cut jumps from the sent question
  to the rendered reply; that is a deliberate jump cut, not a trim of the wait.
- `/api/attack-surface` returns 503 while the AI layer warms. If the legend's
  AI states are missing from the graph, you started recording too early.
- `vscan audit` is ~14s warm, ~50s cold — OSV results cache for 7 days, so do a
  throwaway run first.
- Don't show `.env`. The Baseten key is in it.
