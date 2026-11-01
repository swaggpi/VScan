/* ===========================================================================
   VScan · reachability viewer
   Shape-agnostic: renders whatever node/edge kinds are present. The one
   orchestrated moment is the reachability trace lighting up from an entry
   point down to each dependency it reaches.
   =========================================================================== */
(function () {
  "use strict";

  var REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Edges a reachability trace follows, in BFS order: route first, then calls.
  var TRACE_EDGES = { route_to_handler: true, calls: true };

  // Kinds hidden by default so the canvas reads as a clean layered network:
  // modules, files and docs are structural context, not part of the call-flow
  // spine. Each keeps its filter chip, so any can be toggled back on.
  var OFF_BY_DEFAULT = { module: true, file: true, doc: true };

  // Above this many nodes a graph is unusable as a hairball, so we render a
  // curated security-relevant subgraph instead of every node. The sample app
  // (~33 nodes) stays well under this, so its behavior is unchanged.
  var LARGE_GRAPH = 1200;

  var KIND_LABEL = {
    entrypoint: "entry points", dependency: "dependencies", function: "functions",
    module: "modules", file: "files", doc: "docs"
  };
  var KIND_COLOR = {
    entrypoint: "var(--signal)", dependency: "#6FB8E0", function: "#9FC6E0",
    module: "#4E7493", file: "#4E7493", doc: "#4E7493"
  };

  // The single RED — the ONLY red in the scheme, reserved for a proven
  // exploitable dependency. Cytoscape styles are canvas-rendered, so they take
  // literal colors, not CSS custom properties. Mirrors --alert. ALERT_INK is the
  // light red-pink ring/label tint.
  var ALERT = "#E5484D";
  var ALERT_INK = "#F7A6A0";
  // AI-inferred accent (Phase 2): a violet held apart from the amber reachability
  // signal and the red vulnerability accent, so an inferred edge / likely-reachable
  // marker can never be mistaken for a proven-reachable or exploitable verdict.
  // Mirrors --infer. INFER_INK is the lighter label tint.
  var INFER = "#8E7BF5";
  var INFER_INK = "#C6B2F6";
  // ADVISORY code-level attack-surface accent (Tier-A AI pen-tester). A
  // magenta-purple held apart from EVERY deterministic hue — the amber reachability
  // signal, the red (ALERT) exploitable accent and the violet (INFER) likely
  // marker — so an AI-identified code-level HYPOTHESIS on an entry point can never
  // be read as a proven/confirmed/exploitable verdict, and in particular is clearly
  // NOT the red. One ring for all severities; severity lives in the tooltip/pop-out.
  var DANGER = "#E24FC4";
  var DANGER_INK = "#F3A6E0";
  // Ranking ladders for ordering findings (severity first, then confidence).
  var DANGER_SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  var CONF_RANK = { high: 3, medium: 2, low: 1 };

  var cy = null;
  var graphFitEles = null;  // the collection runLayout framed, reused on refit
  var GRAPH_PAD = 56;       // viewport padding when fitting the diagram
  var model = { nodes: [], edges: [], index: {}, outByKind: {} };
  var visibleKinds = {};
  // Transitive (lockfile-only) dependencies are hidden by default — the
  // "transitive deps" chip flips this. See isInertTransitive() for the guard
  // that keeps a transitive dep that actually matters on the canvas regardless.
  var showTransitive = false;
  var selectedEp = null;

  // Vulnerability overlay state (populated only in bundle mode; empty for a
  // plain {nodes,edges} graph, which keeps the original viewer unchanged).
  var findings = [];          // ranked finding dicts from the bundle
  var vulnByDep = {};         // dep node id -> { findings, kev, reachable, worst, entrypoints }
  var bundleMeta = null;      // { summary, offline, network_ok, notices } or null
  var bundleReach = null;     // bundle.reachability (per-entrypoint reachable chains) or null
  var assessments = [];       // per-endpoint advisory exposure assessments (bundle.assessments)
  var triage = [];            // per-(dep,CVE) advisory exploitability triage (bundle.triage)
  var triageByDep = {};       // dep node id -> [triage entries], built from `triage`
  var usage = [];             // per-dep advisory dynamic-usage investigation (bundle.usage)
  var usageByDep = {};        // dep node id -> usage entry, built from `usage`
  var selectedNodeId = null;  // node whose datasheet the detail panel shows

  // ADVISORY enrichment overlays — live from GET /api/enrichment?repo=<name>, for
  // the scans backed by a live warm repo (ACME "demo" → acme-api, "pluginreports"
  // → plugin-reports). Purely additive; they never touch the deterministic
  // vulnerability verdicts/colors/graph or the reachability model. Three overlays
  // ride together per repo:
  //   • exposure       — Phase 1: internet-facing vs internal, auth, provenance;
  //   • inferred_edges — Phase 2: AI-inferred call edges (dashed violet, Likely view);
  //   • likely_reachable — Phase 2: deps the AI believes a public route likely reaches
  //                        even though static analysis resolved no path (a LEAD, never
  //                        a proven/exploitable result).
  // Empty for every other view and whenever the backend is absent, so the
  // dashboard renders exactly as it does today.
  var exposure = {};              // entrypoint id -> exposure record for the CURRENT view
  var exposureOn = true;          // exposure overlay visible? (legend toggle)
  var currentViewKey = null;      // which switcher view is live
  var currentRepo = null;         // the live repo name for the current view, or null
  // Per-repo cache: one fetch each, kept across view switches so re-visiting a
  // view re-renders instantly. repo -> { fetched, exposure, inferred, likely }.
  var ENRICH = {};
  var expToggleBtn = null;        // the legend's show/hide-overlay toggle

  // Phase-2 current-view enrichment, pointed at the live repo's cache entry by
  // applyViewEnrichment(). Never fed into buildModel()/trace()/computeDepths(),
  // so reachability verdicts, the funnel and the exploitable counts are unchanged.
  var inferredEdges = [];         // [{src,dst,symbol,origin,confidence,rationale,sources}]
  var likelyReachable = [];       // [{dependency_id,name,confidence,via:[node ids]}]
  var likelyByDep = {};           // dep node id -> likely_reachable entry
  var reachMode = "proven";       // "proven" (default) | "likely"

  // ADVISORY Tier-A attack surface — live from GET /api/attack-surface?repo=<name>,
  // for the same live-repo views as the enrichment overlay (acme-api, plugin-reports).
  // Each public entry point may carry AI-identified CODE-LEVEL vulnerability
  // HYPOTHESES in the app's OWN code (SSTI, injection, path traversal, SSRF, …).
  // They are UNVERIFIED leads (provenance "ai-hypothesis", advisory true) and are
  // kept entirely distinct from the deterministic dependency findings/verdicts and
  // the reachability funnel — they never feed buildModel()/trace()/the counts.
  var attackSurface = {};         // ep id -> { label, exposure, findings:[...] } (current view)
  var attackSummary = null;       // { total_findings, by_severity, entrypoints_with_findings }
  var dangerOpen = false;         // Danger Overview panel visible?
  var dangerFocusEp = null;       // entry point the overview is focused on, or null

  // Focused-view state. When a loaded graph exceeds LARGE_GRAPH we render only
  // the security-relevant subgraph; these hold the full-repo totals and the
  // curation counts the banner reports. Empty/false for small graphs.
  var focusedMode = false;
  var focusedMeta = null;     // { epTotal, promEp, clustered, vulnDeps, reachablePaths, fullNodes, fullEdges }
  var repoCounts = {};        // kind -> count across the FULL repo (header "Repository totals")

  // Bundles fetched for the header switcher, cached by view key so switching
  // re-renders instantly without re-fetching.
  var bundleCache = {};

  var el = {
    counts: document.getElementById("counts"),
    layout: document.querySelector(".layout"),
    funnel: document.getElementById("funnel"),
    noise: document.getElementById("noise"),
    eplist: document.getElementById("eplist"),
    epNote: document.getElementById("ep-note"),
    reachBody: document.getElementById("reach-body"),
    vulnBody: document.getElementById("vuln-body"),
    vulnNote: document.getElementById("vuln-note"),
    filters: document.getElementById("filters"),
    stage: document.querySelector(".stage"),
    graph: document.getElementById("graph"),
    tooltip: document.getElementById("tooltip"),
    scanname: document.getElementById("scanname"),
    file: document.getElementById("file"),
    banner: document.getElementById("banner"),
    detail: document.getElementById("detail"),
    detailInner: document.getElementById("detail-inner"),
    zoomIn: document.getElementById("zoom-in"),
    zoomOut: document.getElementById("zoom-out"),
    zoomFit: document.getElementById("zoom-fit"),
    viewDemo: document.getElementById("view-demo"),
    viewPlugin: document.getElementById("view-pluginreports")
  };

  /* ---------------------------------------------------------------- model */
  function buildModel(graph) {
    var nodes = graph.nodes || [];
    var edges = graph.edges || [];
    var index = {}, outByKind = {}, inByDst = {};
    nodes.forEach(function (n) { index[n.id] = n; });
    edges.forEach(function (e) {
      if (!index[e.src] || !index[e.dst]) return; // drop dangling edges
      (outByKind[e.src] || (outByKind[e.src] = [])).push(e);
      (inByDst[e.dst] || (inByDst[e.dst] = [])).push(e); // reverse adjacency
    });
    model = { nodes: nodes, edges: edges, index: index, outByKind: outByKind, inByDst: inByDst };
  }

  function kindsPresent() {
    var seen = {}, order = ["entrypoint", "function", "dependency", "module", "file", "doc"], out = [];
    model.nodes.forEach(function (n) { seen[n.kind] = true; });
    order.forEach(function (k) { if (seen[k]) out.push(k); });
    // any unexpected kinds, appended so the page stays shape-agnostic
    Object.keys(seen).forEach(function (k) { if (out.indexOf(k) < 0) out.push(k); });
    return out;
  }

  /* ---------------------------------------------------------------- reachability */
  // BFS from an entry point over route_to_handler then calls edges.
  function trace(epId) {
    var depth = {}, nodeSet = {}, edgeKey = {}, queue = [epId];
    depth[epId] = 0; nodeSet[epId] = true;
    while (queue.length) {
      var cur = queue.shift();
      var outs = model.outByKind[cur] || [];
      for (var i = 0; i < outs.length; i++) {
        var e = outs[i];
        if (!TRACE_EDGES[e.kind]) continue;
        edgeKey[e.src + "\u0000" + e.dst + "\u0000" + e.kind] = true;
        if (!(e.dst in nodeSet)) {
          nodeSet[e.dst] = true;
          depth[e.dst] = depth[cur] + 1;
          queue.push(e.dst);
        }
      }
    }
    var deps = Object.keys(nodeSet)
      .map(function (id) { return model.index[id]; })
      .filter(function (n) { return n && n.kind === "dependency"; })
      .sort(function (a, b) { return (a.name || a.id).localeCompare(b.name || b.id); });
    return { nodes: nodeSet, edges: edgeKey, depth: depth, deps: deps };
  }

  // Reverse reachability: BFS BACKWARD from a dependency over the SAME trace
  // edges (calls, route_to_handler), following each edge from its dst to its
  // src. This lights every node and edge on any path that REACHES the dep — the
  // full reaching subgraph up to the entry points — not just one incident edge.
  // Depth is hops away from the dependency (the dep is 0), so the energize
  // animation ripples outward from the dep toward the routes that call it.
  function traceReverse(depId) {
    var depth = {}, nodeSet = {}, edgeKey = {}, queue = [depId], head = 0;
    depth[depId] = 0; nodeSet[depId] = true;
    while (head < queue.length) {
      var cur = queue[head++];
      var ins = model.inByDst[cur] || [];
      for (var i = 0; i < ins.length; i++) {
        var e = ins[i];
        if (!TRACE_EDGES[e.kind]) continue;
        edgeKey[e.src + "\u0000" + e.dst + "\u0000" + e.kind] = true;
        if (!(e.src in nodeSet)) {
          nodeSet[e.src] = true;
          depth[e.src] = depth[cur] + 1;
          queue.push(e.src);
        }
      }
    }
    var eps = Object.keys(nodeSet)
      .map(function (id) { return model.index[id]; })
      .filter(function (n) { return n && n.kind === "entrypoint"; })
      .sort(function (a, b) { return labelFor(a).localeCompare(labelFor(b)); });
    return { nodes: nodeSet, edges: edgeKey, depth: depth, entrypoints: eps };
  }

  /* ---------------------------------------------------------------- cytoscape */
  function cyStyle() {
    return [
      // Every node is a neuron: a clean circle (ellipse, width == height). Kind is
      // read from fill and outline, never shape, so the layers stay uniform.
      { selector: "node", style: {
        "label": "data(label)", "font-family": "JetBrains Mono, monospace",
        "font-size": 12, "color": "#BFDCF0", "text-opacity": 0.9, "text-valign": "bottom",
        "text-margin-y": 9, "text-wrap": "ellipsis", "text-max-width": 150,
        // A dark halo lifts labels off the grid, edges and overlapping nodes.
        "text-outline-color": "#081A2C", "text-outline-width": 3, "text-outline-opacity": 0.95,
        "shape": "ellipse", "width": 26, "height": 26, "border-width": 2,
        "background-color": "#4E7493", "border-color": "#6E93B2",
        "transition-property": "background-color, border-color, opacity, width, height, line-color",
        "transition-duration": REDUCED ? "0s" : "260ms"
      }},
      // Dependencies — the output layer. The resting fill is the "no CVE" base of
      // the risk ramp: a muted grey-blue neuron. Vulnerable states warm it up
      // (slate → amber → red) in the risk rules below.
      { selector: 'node[kind = "dependency"]', style: {
        "background-color": "#39485A", "background-opacity": 0.88,
        "border-color": "#4C5E71", "border-width": 2,
        "width": 42, "height": 42, "color": "#B9CEDE"
      }},
      // Functions — the hidden layers. A dim neuron over the dark ground.
      { selector: 'node[kind = "function"]', style: {
        "background-color": "#2C3F54", "background-opacity": 0.72,
        "border-color": "#4E6B86", "border-width": 2,
        "width": 30, "height": 30
      }},
      // Structural kinds (off by default) stay circles too, just small and muted.
      { selector: 'node[kind = "module"]', style: { "background-color": "#2C4660", "border-color": "#4E7493", "width": 24, "height": 24 }},
      { selector: 'node[kind = "file"]', style: { "background-color": "rgba(78,116,147,0.28)", "border-color": "#4E7493", "width": 22, "height": 22 }},
      { selector: 'node[kind = "doc"]', style: { "background-color": "rgba(78,116,147,0.28)", "border-color": "#4E7493", "width": 24, "height": 24 }},
      // Entry points — the input layer. A solid STEEL neuron at the start of the
      // flow — deliberately NOT amber, so it never reads as the amber "reachable"
      // dependency state.
      { selector: 'node[kind = "entrypoint"]', style: {
        "background-color": "#4C8FC7", "background-opacity": 1,
        "border-color": "#9ECAEE", "border-width": 2.5,
        "width": 42, "height": 42, "color": "#CDE2F2", "font-weight": 600
      }},

      /* ADVISORY exposure overlay (live /api/enrichment, demo only): a subtle
         mark on an entry point. INTERNAL keeps a quiet cool-blue halo. PUBLIC is a
         thin DOTTED de-saturated outline — deliberately subtle and NOT a saturated
         colour, so it can't be mistaken for the amber "reachable" state. Declared
         BEFORE the .dim/.lit/.focus/.selected rules so an active trace or a
         selection still overrides it. */
      { selector: 'node[expo = "internal"]', style: {
        "overlay-color": "#6FB8E0", "overlay-opacity": 0.18, "overlay-padding": 6
      }},
      { selector: 'node[expo = "public"]', style: {
        "border-style": "dotted", "border-color": "#AFC3D6", "border-width": 1.5
      }},

      /* focused-view only: the compact stand-in for the entry points that reach
         no vulnerable dependency, so the canvas isn't N loose dots */
      { selector: 'node[kind = "epcluster"]', style: {
        "background-color": "rgba(78,116,147,0.18)", "border-color": "#4E7493",
        "border-width": 1.5, "border-style": "dashed", "shape": "round-rectangle",
        "width": 184, "height": 54, "color": "#8FB2CE", "font-size": 11,
        "text-valign": "center", "text-margin-y": 0, "text-wrap": "wrap",
        "text-max-width": 164, "font-weight": 600
      }},

      /* Dependency risk — a traffic-light ramp by how sure we are the dep can be
         attacked. SOLID FILL = a deterministic/proven state (never a dashed
         advisory ring, never red unless exploitable). Each state is a DISTINCT
         hue, cool→warm:
           no CVE                       = the grey-blue base (above);
           a CVE, code never reaches it = a SLATE fill + a thin slate ring (low concern);
           reachable, not proven exploitable = a solid AMBER fill;
           attacker input provably reaches the call (exploitable) = the ONLY RED,
             a slightly larger node with a light-red ring.
         Rules cascade: vreach overrides slate with amber, tainted overrides amber
         with red (background-fill:solid resets any prior fill). */
      { selector: 'node[vuln = 1]', style: {
        "background-fill": "solid",
        "background-color": "#43566A", "background-opacity": 0.82,
        "border-color": "#56697D", "border-width": 1.5, "color": "#9FB2C3"
      }},
      { selector: 'node[vreach = 1]', style: {
        "background-fill": "solid",
        "background-color": "#F2B134", "background-opacity": 1,
        "border-color": "#F7CE78", "border-width": 2, "color": "#F7CE78"
      }},
      { selector: 'node[tainted = 1]', style: {
        "background-fill": "solid",
        "background-color": ALERT, "background-opacity": 1,
        "border-color": ALERT_INK, "border-width": 2,
        "width": 46, "height": 46, "color": "#FBD5D2", "font-weight": 600
      }},

      /* ADVISORY likely-reachable marker (Phase 2, "Likely" view only). A dep the
         AI believes a public route likely reaches even though static analysis
         resolved no path. A DASHED VIOLET ring + violet label — deliberately
         UNLIKE the red exploitable node, the amber reachable node and the cool lit
         trace, so it reads as a separate, weaker, advisory signal. The dep keeps
         its real risk fill underneath; this only re-skins the ring while the Likely
         view is on (the `likely` flag is 0 in Proven view). Declared AFTER the vuln
         rules so it wins over the risk ring, but BEFORE .dim/.lit/.focus/.selected
         so a trace or selection still overrides. */
      { selector: 'node[likely = 1]', style: {
        "border-color": INFER, "border-width": 3.5, "border-style": "dashed",
        "color": INFER_INK,
        "overlay-color": INFER, "overlay-opacity": 0.16, "overlay-padding": 7
      }},

      /* ADVISORY code-level attack-surface marker (Tier-A AI pen-tester). An entry
         point whose OWN code the AI flagged with a candidate vulnerability gets a
         DASHED magenta-purple ring + a "⚠" glyph prepended to its label (no halo).
         Deliberately UNLIKE every deterministic state — in particular clearly NOT
         the red exploitable dep, and not the dashed-violet LIKELY marker or the
         cool lit trace — so it reads as a separate, weaker, advisory lead. One
         ring for every severity; severity lives in the tooltip/pop-out. Declared
         alongside the other advisory overlays (before .dim/.lit/.focus/.selected)
         so an active trace or a selection still overrides it. */
      { selector: 'node[danger = 1]', style: {
        "border-color": DANGER, "border-width": 3, "border-style": "dashed",
        "color": DANGER_INK
      }},

      // Connections are thin, straight lines between layers — like the synapses
      // of a feed-forward network. No arrowheads by default (direction is the
      // vertical layering, and the amber trace shows the climb when lit).
      { selector: "edge", style: {
        "width": 1, "line-color": "#345570", "curve-style": "straight",
        "target-arrow-shape": "none", "opacity": 0.5,
        "transition-property": "line-color, target-arrow-color, width, opacity",
        "transition-duration": REDUCED ? "0s" : "220ms"
      }},
      // The call-flow spine (route -> handler -> callee) — the synapses that
      // actually carry the network, so slightly more present than the rest.
      { selector: 'edge[kind = "route_to_handler"], edge[kind = "calls"]', style: {
        "curve-style": "straight", "line-color": "#4E7CA3",
        "width": 1, "opacity": 0.6
      }},
      // Structural edges (imports/contains/declares/documents) are context, not
      // flow — faint hairlines so they never fight the spine when toggled on.
      { selector: 'edge[kind = "imports"], edge[kind = "contains"], edge[kind = "declares"], edge[kind = "documents"]', style: {
        "line-color": "#283F57", "width": 0.7, "opacity": 0.32
      }},
      // `documents` edges are doc-provenance (a doc mentions a node), not code
      // flow, so they read as dotted hairlines. Derived purely from edge.kind —
      // present in any bundle, independent of the live exposure overlay.
      { selector: 'edge[kind = "documents"]', style: { "line-style": "dotted" }},

      /* ADVISORY inferred call edges (Phase 2, "Likely" view only). An AI-inferred
         call the structural scan could not resolve (e.g. a reflective getattr).
         DASHED and VIOLET so it reads clearly apart from the solid deterministic
         call spine — a hypothesis, not a proven edge. Hidden (display:none) in
         Proven view and excluded from the layout, so Proven renders exactly as
         before. These edges are display-only: they are NOT added to the data model
         or the reachability trace, so verdicts and counts never change. */
      { selector: 'edge[inferred]', style: {
        "line-style": "dashed", "line-dash-pattern": [6, 4],
        "line-color": INFER, "width": 1.8, "opacity": 0.85,
        "curve-style": "straight",
        "target-arrow-shape": "triangle", "target-arrow-color": INFER, "arrow-scale": 0.7
      }},
      /* Keep an inferred edge faintly visible even when a trace dims the graph,
         so the dashed hypothesis does not vanish under a selection. */
      { selector: 'edge[inferred].dim', style: { "opacity": 0.2 }},

      /* off the call-flow spine (unreached functions, module/file/doc) — kept
         visible but visually secondary. Declared before .dim so an active trace
         still dims these further; .lit/.focus come later and override it. */
      { selector: "node.offspine", style: { "opacity": 0.4, "font-size": 11, "text-opacity": 0.75 } },

      /* dimmed (something else is selected) */
      { selector: ".dim", style: { "opacity": 0.12 } },
      { selector: "edge.dim", style: { "opacity": 0.06 } },

      /* live reachability trace — the one hot signal. A bright COOL glow
         (#8FE3FF fill / #CFEFFF ring) so the selected/traced PATH is clearly
         distinct from the amber "reachable" dependency state. */
      { selector: "node.lit", style: {
        "background-fill": "solid",
        "background-color": "#8FE3FF", "border-color": "#CFEFFF",
        "color": "#CFEFFF", "border-width": 2.5, "opacity": 1,
        "overlay-color": "#8FE3FF", "overlay-opacity": 0.22, "overlay-padding": 7
      }},
      { selector: 'node.lit[kind = "function"]', style: { "background-color": "#8FE3FF", "background-opacity": 0.9 } },
      { selector: 'node.lit[kind = "entrypoint"]', style: { "background-color": "#8FE3FF", "width": 46, "height": 46, "overlay-padding": 9 } },
      // The lit trace is a bright cool straight line climbing the layers, with a
      // small arrowhead to show the direction of the call chain.
      { selector: "edge.lit", style: {
        "curve-style": "straight",
        "line-color": "#8FE3FF", "target-arrow-color": "#8FE3FF",
        "target-arrow-shape": "triangle", "arrow-scale": 0.8,
        "width": 2.4, "opacity": 1,
        "overlay-color": "#8FE3FF", "overlay-opacity": 0.12, "overlay-padding": 2
      }},
      /* a lit vulnerable dep keeps its RED endpoint: cool path -> red endpoint */
      { selector: 'node.lit[vuln = 1]', style: {
        "border-color": ALERT_INK, "border-width": 3.5,
        "overlay-color": ALERT, "overlay-opacity": 0.24, "overlay-padding": 8
      }},
      /* A lit LIKELY-reachable dep stays VIOLET (advisory), never the cool proven
         glow or the red proven-reached endpoint — declared last so it wins over
         node.lit / node.lit[vuln=1] when a likely dep's inferred path is lit. */
      { selector: 'node.lit[likely = 1]', style: {
        "background-fill": "solid", "background-color": INFER,
        "border-color": "#B9A9F7", "border-width": 2.5,
        "overlay-color": INFER, "overlay-opacity": 0.22, "overlay-padding": 8
      }},
      /* A lit inferred HOP stays violet + dashed (never the cool proven line), so
         an AI-inferred likely path reads as advisory even when highlighted. */
      { selector: 'edge[inferred].lit', style: {
        "line-style": "dashed", "line-color": INFER, "target-arrow-color": INFER,
        "opacity": 1, "width": 2.2,
        "overlay-color": INFER, "overlay-opacity": 0.14, "overlay-padding": 2
      }},

      /* neighborhood focus (click a node) */
      { selector: ".focus", style: { "opacity": 1 } },
      { selector: "node.focus", style: { "border-color": "#CFE4F2" } },
      { selector: "edge.focus", style: { "curve-style": "straight", "line-color": "#6FB8E0", "opacity": 0.9, "width": 1.6 } },

      /* a lit, focused or selected node shows its full label, not an ellipsis */
      { selector: "node.lit, node.focus, node.selected", style: { "text-wrap": "wrap", "text-max-width": 200, "z-index": 30 } },

      /* the node whose datasheet is open in the detail panel — a bright halo so
         it's obvious which part the panel describes. Declared last to win. */
      { selector: "node.selected", style: {
        "overlay-color": "#CFE4F2", "overlay-opacity": 0.16, "overlay-padding": 11,
        "text-opacity": 1
      }}
    ];
  }

  function toCy() {
    var eles = [];
    model.nodes.forEach(function (n) {
      var vs = vulnByDep[n.id];
      // ADVISORY code-level danger marker (entry points only): worst severity of
      // this route's AI-identified attack-surface findings, "" when none. Drives
      // the distinct magenta danger ring + the "⚠" label glyph; never touches any
      // vuln flag below or the reachability model.
      var dsev = n.kind === "entrypoint" ? dangerSevFor(n.id) : "";
      eles.push({ data: {
        id: n.id, kind: n.kind,
        label: (dsev ? "⚠ " : "") + labelFor(n),
        name: n.name || n.id,
        // Overlay flags (0 unless an audit bundle marked this dependency).
        vuln: vs ? 1 : 0,
        vreach: vs && vs.reachable ? 1 : 0,
        kev: vs && vs.kev ? 1 : 0,
        // Deterministic escalation flags: the vulnerable function was reached
        // (symbol_match=confirmed), and attacker input reaches it (taint=tainted).
        confirmed: vs && vs.symbolConfirmed ? 1 : 0,
        tainted: vs && vs.tainted ? 1 : 0,
        // ADVISORY exposure tag (entry points only, "" otherwise). Drives the
        // subtle internal/public ring; never affects any vuln flag above.
        expo: n.kind === "entrypoint" ? exposureTagFor(n.id) : "",
        // ADVISORY code-level danger marker (entry points only). "danger" gates
        // the magenta ring; "dangersev" grades it by worst severity.
        danger: dsev ? 1 : 0,
        dangersev: dsev
      }});
    });
    model.edges.forEach(function (e) {
      if (!model.index[e.src] || !model.index[e.dst]) return;
      eles.push({ data: {
        id: "e\u0000" + e.src + "\u0000" + e.dst + "\u0000" + e.kind,
        source: e.src, target: e.dst, kind: e.kind,
        tkey: e.src + "\u0000" + e.dst + "\u0000" + e.kind
      }});
    });
    // Focused view: one cluster node stands in for the entry points that reach
    // nothing vulnerable. It carries no edges and is not part of the model, so
    // the filters, entry-point list and reachability trace never touch it.
    if (focusedMode && focusedMeta && focusedMeta.clustered > 0) {
      eles.push({ data: {
        id: EPCLUSTER_ID, kind: "epcluster",
        label: "+" + focusedMeta.clustered + " entry points\nreach no vulnerable dep",
        name: focusedMeta.clustered + " more entry points"
      }});
    }
    return eles;
  }

  var EPCLUSTER_ID = "__vr_epcluster__";

  function labelFor(n) {
    if (n.kind === "entrypoint") {
      var a = n.attrs || {};
      return (a.method ? a.method + " " : "") + (a.path || n.name || n.id);
    }
    if (n.kind === "dependency" && n.attrs && n.attrs.version) {
      return (n.name || n.id) + " " + n.attrs.version;
    }
    return n.name || n.id;
  }

  function renderGraph() {
    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({
      container: el.graph,
      elements: toCy(),
      style: cyStyle(),
      // Continuous, fluid zoom: a low wheel sensitivity turns each notch into a
      // fine increment rather than a jump, so the wheel feels analog, not stepped.
      minZoom: 0.08, maxZoom: 4,
      wheelSensitivity: 0.2,
      zoomingEnabled: true, userZoomingEnabled: true,
      panningEnabled: true, userPanningEnabled: true,
      boxSelectionEnabled: false
    });
    applyFilter(false);
    bindGraphEvents();
  }

  // Call-depth of every node = shortest number of hops from ANY entry point,
  // following route_to_handler then calls edges (multi-source BFS). Entry points
  // are depth 0; a handler called by a route is depth 1; and so on toward the
  // dependencies. A node absent from the map is not reachable from any route.
  // Computed from the full model (a graph property), independent of what kinds
  // are currently filtered in/out.
  function computeDepths() {
    var depth = {}, queue = [], head = 0;
    model.nodes.forEach(function (n) {
      if (n.kind === "entrypoint") { depth[n.id] = 0; queue.push(n.id); }
    });
    while (head < queue.length) {
      var cur = queue[head++];
      var outs = model.outByKind[cur] || [];
      for (var i = 0; i < outs.length; i++) {
        var e = outs[i];
        if (!TRACE_EDGES[e.kind]) continue;
        if (!(e.dst in depth)) {
          depth[e.dst] = depth[cur] + 1;
          queue.push(e.dst);
        }
      }
    }
    return depth;
  }

  // Explicit LAYERED left-to-right placement (a preset layout we compute, not a
  // force/breadthfirst layout), so the diagram reads as a pipeline: a public
  // entry point on the LEFT flows RIGHTWARD through call layers to the dependency
  // it reaches on the RIGHT. Columns, left (x small) to right:
  //   • LEFT band:   all `entrypoint` nodes (and the focused-view "+N" cluster).
  //   • MIDDLE cols: `function` nodes in vertical layers by call depth — deeper
  //                  functions (closer to a dependency) sit further RIGHT.
  //   • RIGHT band:  all `dependency` nodes (reachable or disconnected alike).
  // Within a column nodes stack vertically, barycentre-aligned to their
  // neighbours so edges stay short and crossings are few. Unreached functions are
  // hidden by default (see applyFilter), so the spine is all that remains. Any
  // module/file/doc toggled back on is not part of the call-flow spine: those go
  // on a dim shelf BELOW the pipeline, visually secondary. Only currently-visible
  // nodes are distributed, so toggling a kind re-centers the columns cleanly.
  var LAYER_W = 360;    // x-spacing between call-depth columns (left -> right)
  var LANE_H = 84;      // y-spacing between stacked nodes within a column
  var OFF_COL_W = 150;  // off-spine shelf column width
  var OFF_ROW_H = 52;   // off-spine shelf row height
  // A single call-depth column with very many nodes (e.g. a ~50 entry
  // points) would stack into one absurdly tall strip, so the whole diagram
  // shrinks to a sliver when fitted. Past MAX_ROWS a layer wraps into a few
  // vertical sub-columns — a tidy block that keeps the left-to-right layering
  // while bringing the aspect ratio back toward the canvas. Small layers (the
  // demo's handful) never trip this, so their barycentre alignment is preserved.
  var MAX_ROWS = 8;     // wrap a layer taller than this into sub-columns
  var SUB_W = 132;      // horizontal gap between a layer's wrapped sub-columns

  // Order-preserving 1D packing: given each node's desired x (already in layer
  // order), return positions that keep a minimum `gap` between neighbours while
  // staying as close as possible to the desired x's (least-squares). This is the
  // pool-adjacent-violators / isotonic-regression solution: substituting
  // t[i] = desired[i] - i*gap turns the min-gap constraint into a plain
  // "non-decreasing" one, which PAV solves exactly in O(n).
  function packWithGap(desired, gap) {
    var n = desired.length;
    if (!n) return [];
    var blocks = []; // each: { sum, count } over a run with a common fitted value
    for (var i = 0; i < n; i++) {
      blocks.push({ sum: desired[i] - i * gap, count: 1 });
      while (blocks.length > 1) {
        var a = blocks[blocks.length - 2], b = blocks[blocks.length - 1];
        if (a.sum / a.count <= b.sum / b.count) break; // already non-decreasing
        blocks.pop(); blocks.pop();
        blocks.push({ sum: a.sum + b.sum, count: a.count + b.count });
      }
    }
    var pos = [], k = 0;
    blocks.forEach(function (blk) {
      var mean = blk.sum / blk.count;
      for (var j = 0; j < blk.count; j++, k++) pos.push(mean + k * gap);
    });
    return pos;
  }

  function runLayout(depth) {
    depth = depth || computeDepths();
    var vis = cy.nodes(":visible");

    // Deepest visible reachable function sets which column the dependency band
    // sits in (always one past the deepest function so deps are furthest right).
    var maxFuncDepth = 0;
    vis.forEach(function (n) {
      if (n.data("kind") === "function" && (n.id() in depth)) {
        maxFuncDepth = Math.max(maxFuncDepth, depth[n.id()]);
      }
    });
    var depsLayer = maxFuncDepth + 1; // dependency band always rightmost

    var layers = {};     // layerIndex -> [nodes] on the call-flow spine
    var offspine = [];   // module/file/doc + unknowns, only if toggled on
    var spine = cy.collection();
    var inSpine = {};
    function push(L, n) {
      (layers[L] || (layers[L] = [])).push(n);
      spine = spine.add(n); inSpine[n.id()] = true;
    }

    vis.forEach(function (n) {
      var k = n.data("kind");
      if (k === "entrypoint" || k === "epcluster") {
        push(0, n);                       // left band — the input layer
      } else if (k === "dependency") {
        push(depsLayer, n);               // right band — the output layer
      } else if (k === "function" && (n.id() in depth)) {
        push(depth[n.id()], n);           // middle columns: deeper = further right
      } else {
        offspine.push(n);                 // off-spine shelf
      }
    });

    function sortKey(n) { return String(n.data("label") || n.data("name") || n.id()); }
    var layerKeys = Object.keys(layers).map(Number).sort(function (a, b) { return a - b; });

    // Adjacency among spine nodes (undirected), for barycentre alignment.
    var adj = {};
    spine.forEach(function (n) { adj[n.id()] = []; });
    cy.edges(":visible").forEach(function (e) {
      if (e.data("inferred")) return; // advisory overlay — never shifts the layout
      var s = e.source().id(), t = e.target().id();
      if (inSpine[s] && inSpine[t]) { adj[s].push(t); adj[t].push(s); }
    });

    // Start from an even, centred, deterministic order per column (the cross axis
    // is now vertical: `ypos` positions nodes top-to-bottom within a column).
    var ypos = {};
    layerKeys.forEach(function (k) {
      var arr = layers[k];
      arr.sort(function (a, b) { return sortKey(a).localeCompare(sortKey(b)); });
      var c = arr.length;
      arr.forEach(function (n, i) { ypos[n.id()] = (i - (c - 1) / 2) * LANE_H; });
    });

    // Barycentre sweeps: pull each node toward the mean y of its neighbours, then
    // repack the column (min gap, least-squares to those targets). Alternating the
    // sweep direction lets the alignment propagate across every column, so edges
    // stay short overall and a node between two others lands near their midpoint —
    // trading a few big jumps for many small ones. Pure placement; verdicts/edges
    // are untouched.
    var SWEEPS = 12;
    for (var s = 0; s < SWEEPS; s++) {
      var order = (s % 2 === 0) ? layerKeys : layerKeys.slice().reverse();
      order.forEach(function (k) {
        var arr = layers[k];
        if (!arr.length) return;
        var desired = arr.map(function (n) {
          var nb = adj[n.id()];
          if (!nb.length) return ypos[n.id()];
          var sum = 0;
          for (var i = 0; i < nb.length; i++) sum += ypos[nb[i]];
          return sum / nb.length;
        });
        // Reorder by barycentre (reduces crossings); stable via current y then key.
        var idx = arr.map(function (_, i) { return i; });
        idx.sort(function (a, b) {
          return (desired[a] - desired[b]) ||
            (ypos[arr[a].id()] - ypos[arr[b].id()]) ||
            sortKey(arr[a]).localeCompare(sortKey(arr[b]));
        });
        var ordered = idx.map(function (i) { return arr[i]; });
        var placed = packWithGap(idx.map(function (i) { return desired[i]; }), LANE_H);
        ordered.forEach(function (n, i) { ypos[n.id()] = placed[i]; });
        layers[k] = ordered; // carry the improved order into the next sweep
      });
    }

    cy.batch(function () {
      cy.nodes().removeClass("offspine");

      // Walk the layers left to right, advancing an x cursor. A normal layer is
      // one column placed at its barycentre y; an over-tall layer wraps into a
      // grid of sub-columns (column-major, so the barycentre order still reads
      // top-to-bottom within each sub-column) and widens the cursor accordingly.
      var maxAbsY = 0, cursorX = 0, spineWidth = 0;
      layerKeys.forEach(function (k) {
        var arr = layers[k], c = arr.length;
        var subCols = Math.max(1, Math.ceil(c / MAX_ROWS));
        if (subCols === 1) {
          arr.forEach(function (n) {
            var y = ypos[n.id()];
            n.position({ x: cursorX, y: y });
            if (Math.abs(y) > maxAbsY) maxAbsY = Math.abs(y);
          });
          spineWidth = cursorX;
          cursorX += LAYER_W;
        } else {
          var rows = Math.ceil(c / subCols);
          arr.forEach(function (n, i) {
            var col = Math.floor(i / rows), row = i % rows;
            var y = (row - (rows - 1) / 2) * LANE_H;
            n.position({ x: cursorX + col * SUB_W, y: y });
            if (Math.abs(y) > maxAbsY) maxAbsY = Math.abs(y);
          });
          spineWidth = cursorX + (subCols - 1) * SUB_W;
          cursorX = spineWidth + LAYER_W;
        }
      });

      if (offspine.length) {
        offspine.sort(function (a, b) { return sortKey(a).localeCompare(sortKey(b)); });
        offspine.forEach(function (n) { n.addClass("offspine"); });
        // A compact grid BELOW the pipeline, filling row by row so it stays a tidy
        // band rather than one long run.
        var perRow = Math.max(1, Math.floor((spineWidth || LAYER_W) / OFF_COL_W) + 1);
        var offY0 = maxAbsY + LANE_H * 1.8;
        offspine.forEach(function (n, i) {
          var row = Math.floor(i / perRow), col = i % perRow;
          n.position({ x: (col - (perRow - 1) / 2) * OFF_COL_W, y: offY0 + row * OFF_ROW_H });
        });
      }
    });

    // Frame the clean pipeline itself: fit to the spine so the columns stay
    // centred even when a dim off-spine shelf exists below. The "fit everything"
    // zoom control still frames the shelf when the user wants it.
    graphFitEles = spine.length ? spine : cy.nodes(":visible");
    cy.fit(graphFitEles, GRAPH_PAD);
  }

  // A dependency declared only in a lockfile (attrs.direct === false) — pulled in
  // transitively, never named in the manifest.
  function isTransitiveDep(n) {
    return !!(n && n.kind === "dependency" && n.attrs && n.attrs.direct === false);
  }
  // Does a transitive dep earn a spot on the canvas? Yes if a public route proved
  // to reach it (a reachable finding), or if an actual call/route edge lands on it
  // (it sits on the reach spine). The structural `declares` edge from the manifest
  // does NOT count — every transitive dep carries one, so it can't separate the
  // inert lockfile dots from the ones that matter. Such a dep stays visible even
  // when the transitive chip is off, so we never hide one that matters.
  function transitiveMatters(id) {
    var vs = vulnByDep[id];
    if (vs && vs.reachable) return true;
    return (model.inByDst[id] || []).some(function (e) { return TRACE_EDGES[e.kind]; });
  }
  function isInertTransitive(id) {
    var n = model.index[id];
    return isTransitiveDep(n) && !transitiveMatters(id);
  }

  function applyFilter(preserveSelection) {
    var depth = computeDepths();
    cy.batch(function () {
      cy.nodes().forEach(function (node) {
        var kind = node.data("kind");
        var show = visibleKinds[kind] !== false;
        // Keep the network clean: a function not reachable from any entry point is
        // not on the call-flow spine, so it (and its edges) stay hidden by default.
        if (show && kind === "function" && !(node.id() in depth)) show = false;
        // Inert transitive deps (lockfile-only, edge-less, not reachable) are dots
        // that clutter the graph, so they stay hidden until the transitive chip is
        // on. In focusedMode the curated subgraph already holds only vulnerable +
        // reachable nodes, so any transitive dep present there survives transitiveMatters
        // and this never double-hides it.
        if (show && !showTransitive && isInertTransitive(node.id())) show = false;
        node.style("display", show ? "element" : "none");
      });
    });
    runLayout(depth);
    if (preserveSelection && selectedEp) lightTrace(selectedEp, true);
  }

  /* ---------------------------------------------------------------- trace lighting */
  function clearHighlight() {
    cy.elements().removeClass("lit dim focus");
    el.stage.classList.remove("is-traced");
  }

  // Light a precomputed reachability set, rippling by BFS depth. `edgeEnd` says
  // which endpoint's depth beats an edge: "target" for a forward trace (signal
  // climbs from entry toward dep), "source" for a reverse trace (signal ripples
  // from the dep outward toward the routes that reach it).
  function energize(res, instant, edgeEnd) {
    clearHighlight();
    el.stage.classList.add("is-traced");
    cy.elements().addClass("dim");

    var litNodes = cy.nodes().filter(function (n) { return res.nodes[n.id()]; });
    var litEdges = cy.edges().filter(function (e) { return res.edges[e.data("tkey")]; });

    if (REDUCED || instant) {
      litNodes.removeClass("dim").addClass("lit");
      litEdges.removeClass("dim").addClass("lit");
      return;
    }
    var byDepth = {};
    litNodes.forEach(function (n) {
      var d = res.depth[n.id()] || 0;
      (byDepth[d] || (byDepth[d] = [])).push(n);
    });
    var step = 150;
    Object.keys(byDepth).sort(function (a, b) { return a - b; }).forEach(function (d) {
      setTimeout(function () {
        byDepth[d].forEach(function (n) { n.removeClass("dim").addClass("lit"); });
        litEdges.forEach(function (e) {
          var endNode = edgeEnd === "source" ? e.source() : e.target();
          if ((res.depth[endNode.id()] || 0) === Number(d)) e.removeClass("dim").addClass("lit");
        });
      }, Number(d) * step);
    });
  }

  function lightTrace(epId, instant) {
    selectedEp = epId;
    var res = trace(epId);
    energize(res, instant, "target");
    renderReach(epId, res);
    updateEpButtons(epId);
    // Selecting an entry point lights its path AND opens its datasheet.
    if (model.index[epId]) showDetail(model.index[epId]);
  }

  // Selecting a dependency lights its FULL reaching subgraph (reverse BFS), then
  // opens its datasheet. This is the fix for the old behaviour that lit only one
  // incident edge/node. Works identically in the focused big-graph view, where
  // the reverse BFS simply runs over the curated subgraph's nodes and edges.
  function lightReverseTrace(depId, instant) {
    selectedEp = null;
    updateEpButtons(null);
    var res = traceReverse(depId);
    // A likely-reachable dep has no resolved reaching path (its only link is the
    // AI-inferred hop, which is display-only and never in the trace model). Light
    // its full inferred `via` chain end-to-end instead, so the path spans the whole
    // graph (entry -> functions -> dep) rather than leaving the dep unlit.
    var likely = likelyByDep[depId];
    if (likely && (!res.entrypoints || !res.entrypoints.length) && lightVia(likely)) {
      renderReachReverse(depId, res);
      if (model.index[depId]) showDetail(model.index[depId]);
      return;
    }
    energize(res, instant, "source");
    renderReachReverse(depId, res);
    if (model.index[depId]) showDetail(model.index[depId]);
  }

  // Light the AI-inferred reaching path for a likely-reachable dep: every node on
  // its `via` chain and the edge between each consecutive pair. The final hop is
  // the inferred (violet, dashed) edge and the endpoint is the likely dep — both
  // keep their advisory violet styling (edge[inferred].lit / node.lit[likely=1]),
  // so a highlighted likely path never reads as a proven one. Returns false when
  // there is no usable via chain, so the caller falls back to the normal trace.
  function lightVia(likely) {
    if (!cy || !likely || !Array.isArray(likely.via) || likely.via.length < 2) return false;
    clearHighlight();
    el.stage.classList.add("is-traced");
    cy.elements().addClass("dim");
    var via = likely.via, lit = 0;
    for (var i = 0; i < via.length; i++) {
      var n = cy.getElementById(via[i]);
      if (n && n.length) { n.removeClass("dim").addClass("lit"); lit++; }
    }
    for (var j = 0; j < via.length - 1; j++) {
      (function (a, b) {
        cy.edges().forEach(function (ed) {
          if (ed.source().id() === a && ed.target().id() === b) ed.removeClass("dim").addClass("lit");
        });
      })(via[j], via[j + 1]);
    }
    return lit > 0;
  }

  function focusNeighborhood(node) {
    selectedEp = null;
    updateEpButtons(null);
    renderReachEmptyFocus(node);
    clearHighlight();
    el.stage.classList.add("is-traced");
    cy.elements().addClass("dim");
    var hood = node.closedNeighborhood().filter(":visible");
    hood.removeClass("dim").addClass("focus");
  }

  function resetView() {
    selectedEp = null;
    clearHighlight();
    updateEpButtons(null);
    renderReachInitial();
    clearDetail();
  }

  /* ---------------------------------------------------------------- panels */
  function renderCounts() {
    // The slim topbar no longer carries stat tiles (the funnel strip is the
    // headline value), so this is a no-op unless a counts element is present.
    if (!el.counts) return;
    // Full-repo totals, so the header reads as "Repository totals" even when the
    // canvas shows only the focused subgraph.
    var counts = repoCounts;
    var order = [
      ["file", "files"], ["dependency", "dependencies"], ["function", "functions"], ["entrypoint", "entry points"]
    ];
    el.counts.innerHTML = "";
    order.forEach(function (pair) {
      if (!(pair[0] in counts)) return;
      var div = document.createElement("div");
      var dt = document.createElement("dt"); dt.textContent = pair[1];
      var dd = document.createElement("dd"); dd.textContent = counts[pair[0]];
      if (pair[0] === "entrypoint") dd.className = "is-signal";
      div.appendChild(dt); div.appendChild(dd);
      el.counts.appendChild(div);
    });

    // Vulnerability stats, appended as a second group only in bundle mode.
    if (bundleMeta && bundleMeta.summary) {
      var s = bundleMeta.summary;
      var vuln = [
        ["vulnerable deps", s.vulnerable_dependencies, "is-alert", true],
        ["reachable vulns", s.reachable_vulnerabilities, "is-alert", false],
        ["actively exploited", s.kev_vulnerabilities, "is-alert", false]
      ];
      vuln.forEach(function (row, i) {
        if (row[1] == null) return;
        var div = document.createElement("div");
        if (i === 0) div.className = "counts__vuln-lead";
        var dt = document.createElement("dt"); dt.textContent = row[0];
        var dd = document.createElement("dd"); dd.textContent = row[1];
        if (row[1] > 0) dd.className = row[2];
        div.appendChild(dt); div.appendChild(dd);
        el.counts.appendChild(div);
      });
    }
  }

  function groupNum(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ","); }

  // The focused-view notice. States the curation plainly: how many entry points
  // exist, how many reach a vulnerable dependency, how many are grouped, and the
  // full-graph size we chose not to render.
  function renderBanner() {
    if (!focusedMode || !focusedMeta) {
      el.banner.hidden = true;
      el.banner.innerHTML = "";
      return;
    }
    var m = focusedMeta;
    var reach = m.reachablePaths + " reachable path" + (m.reachablePaths === 1 ? "" : "s");
    el.banner.hidden = false;
    el.banner.innerHTML =
      '<span class="banner__lead">Large repository — focused security view</span>' +
      '<span>' + groupNum(m.epTotal) + ' entry points (<b>' + m.promEp +
      '</b> reach a vulnerable dependency, ' + m.clustered + ' grouped) · ' +
      m.vulnDeps + ' vulnerable dependencies · <b>' + reach + '</b></span>' +
      '<span class="banner__full">Full graph: ' + groupNum(m.fullNodes) + ' nodes, ' +
      groupNum(m.fullEdges) + ' edges — not rendered.</span>';
  }

  // The Impact funnel strip: the headline, shown only in bundle mode. Five stages
  // narrowing left -> right from every dependency down to the proven-exploitable
  // few, so the eye lands on the dangerous end. Renders correctly when any count
  // is 0 (a zero stage reads neutral, never a false red alarm). Labels mirror
  // scanner/correlate/report.py funnel_line.
  function renderFunnel() {
    if (!el.funnel) return;
    if (!bundleMeta || !bundleMeta.summary) {
      el.funnel.hidden = true;
      el.funnel.innerHTML = "";
      renderNoise(null);
      return;
    }
    var s = bundleMeta.summary;
    var stages = [
      { n: s.total_dependencies,               label: "dependencies",               tone: "neutral",
        sub: (s.transitive_dependencies > 0
          ? groupNum(s.direct_dependencies || 0) + " direct · " + groupNum(s.transitive_dependencies) + " transitive"
          : null) },
      { n: s.total_vulnerabilities,            label: "known CVEs",                 tone: "neutral" },
      { n: s.reachable_vulnerabilities,        label: "reachable",                  tone: "neutral" },
      { n: s.symbol_confirmed_vulnerabilities, label: "vulnerable-function confirmed", tone: "confirmed" },
      { n: s.taint_confirmed_vulnerabilities,  label: "exploitable",                tone: "exploit",
        sub: "attacker input reaches the call" }
    ];
    var html = "";
    stages.forEach(function (st, i) {
      if (i) html += '<span class="funnel__arrow" aria-hidden="true">&rarr;</span>';
      var n = (st.n == null ? 0 : st.n);
      html += '<div class="funnel__stage funnel__stage--' + st.tone +
        ' funnel__stage--i' + i + (n === 0 ? " is-zero" : "") + '">' +
        '<span class="funnel__num">' + groupNum(n) + '</span>' +
        '<span class="funnel__label">' + esc(st.label) + '</span>' +
        (st.sub ? '<span class="funnel__sub">' + esc(st.sub) + '</span>' : '') +
        '</div>';
    });
    el.funnel.innerHTML = html;
    el.funnel.hidden = false;
    renderNoise(s);
  }

  // The "vs. a conventional scanner" line under the funnel. Every number comes
  // from the loaded bundle's summary: total_vulnerabilities is what a
  // conventional scanner would flag, taint_confirmed_vulnerabilities is what
  // VScan proves exploitable; the % is the share of alerts removed. Floored to
  // one decimal and capped at 99.9 while anything is exploitable, so it never
  // rounds up to a claim of "100%". Hidden when the bundle has no CVE count.
  function renderNoise(s) {
    if (!el.noise) return;
    var total = s ? s.total_vulnerabilities : null;
    if (typeof total !== "number" || !(total > 0)) {
      el.noise.hidden = true;
      el.noise.innerHTML = "";
      return;
    }
    var exploit = Math.max(0, Math.min(total, s.taint_confirmed_vulnerabilities || 0));
    var pct = Math.floor((1 - exploit / total) * 1000) / 10;
    if (exploit > 0 && pct > 99.9) pct = 99.9;
    var pctTxt = String(pct) + "%";
    var alerts = groupNum(total) + " alert" + (total === 1 ? "" : "s");
    var msg;
    if (exploit === 0) {
      // Honesty: with nothing proven-exploitable we state a TAINT-SCOPED result —
      // zero dependencies with a proven exploit path — and never claim proof that
      // none are exploitable or that the app is safe (this fires on the SSTI demo).
      msg = 'A conventional scanner would flag <b>' + alerts + '</b>. ' +
        'VScan found <b>0 dependencies with a proven exploit path</b> &mdash; ' +
        'proven dependency taint paths only, not a guarantee the app is safe.';
    } else {
      var verdict = exploit === total
        ? "VScan proves <b>all " + groupNum(exploit) + "</b> " + (exploit === 1 ? "is" : "are") + " exploitable"
        : "VScan proves <b>" + groupNum(exploit) + "</b> " + (exploit === 1 ? "is" : "are") + " exploitable";
      msg = 'A conventional scanner would flag <b>' + alerts + '</b>. ' + verdict +
        (exploit === total ? "." : ' &mdash; <b class="noise__pct">' + pctTxt + ' noise cut.</b>');
    }
    el.noise.innerHTML = msg;
    el.noise.style.setProperty("--noise-removed", pct + "%");
    el.noise.hidden = false;
  }

  // The worst vulnerability a route deterministically reaches, or null. Picks
  // tainted (exploitable) over symbol-confirmed over bare reachable, then by
  // severity. Advisory AI states never count here — this list is deterministic.
  function worstReachedVuln(epId) {
    var res = trace(epId);
    var epNode = model.index[epId];
    var epLabel = epNode ? labelFor(epNode) : "";
    var worst = null;
    res.deps.forEach(function (d) {
      var vs = vulnByDep[d.id];
      if (!vs) return;
      // EXPLOITABLE only when a PROVEN taint path runs THROUGH this endpoint — the
      // dep has a tainted finding whose taint_evidence.entrypoint is this route's
      // label. A dep tainted via some OTHER route is only REACHABLE from here.
      var taintedHere = !!(vs.tainted &&
        vs.taintEntrypoints && vs.taintEntrypoints.indexOf(epLabel) >= 0);
      // Ranking keeps the deterministic escalation ladder (global tainted) so the
      // same dep is picked as the route's worst and the list order stays stable;
      // only the verdict LABEL below reflects whether taint flows through here.
      var rank = (vs.tainted ? 3 : (vs.symbolConfirmed ? 2 : 1)) * 10 + (vs.worst || 0);
      if (!worst || rank > worst.rank) {
        worst = { dep: d, rank: rank, tainted: taintedHere,
                  verdict: taintedHere ? "EXPLOITABLE" : "REACHABLE" };
      }
    });
    return worst;
  }

  // Left panel: ONLY vulnerable endpoints — public routes that reach at least one
  // dependency with a known vulnerability. Each row shows method + path, a PUBLIC
  // mark when exposure says so, and the single worst vuln it exposes (dependency +
  // deterministic verdict). Clicking lights the trace AND opens the pop-out
  // (lightTrace does both). Deep detail lives in the pop-out and the chat agent.
  function renderEntryPoints() {
    if (!el.eplist) return;
    el.eplist.innerHTML = "";
    el.eplist.classList.remove("eplist--grouped");

    var rows = [];
    model.nodes.forEach(function (n) {
      if (n.kind !== "entrypoint") return;
      var w = worstReachedVuln(n.id);
      if (w) rows.push({ ep: n, worst: w });
    });
    rows.sort(function (a, b) {
      return (b.worst.tainted - a.worst.tainted) ||
        labelFor(a.ep).localeCompare(labelFor(b.ep));
    });

    // Warming note while the per-repo overlays are still loading on the backend.
    var enEp = currentRepo && ENRICH[currentRepo];
    var warming = !!(enEp && ((enEp.warming && !enEp.fetched) || (enEp.attackWarming && !enEp.attackFetched)));

    if (!rows.length) {
      if (el.epNote) {
        el.epNote.textContent = warming
          ? "Analysis still warming…"
          : "No public route reaches a known vulnerability in this scan.";
      }
      var li0 = document.createElement("li");
      li0.innerHTML = '<p class="ep__empty">No reachable vulnerabilities. ' +
        'The graph still shows the full attack surface, including any AI-advisory leads.</p>';
      el.eplist.appendChild(li0);
      return;
    }

    if (el.epNote) {
      el.epNote.textContent = rows.length +
        (rows.length === 1 ? " public route reaches" : " public routes reach") +
        " a known vulnerability." + (warming ? "  ·  analysis still warming…" : "");
    }

    rows.forEach(function (r) {
      var n = r.ep, a = n.attrs || {}, w = r.worst;
      var li = document.createElement("li");
      var btn = document.createElement("button");
      btn.className = "ep";
      btn.type = "button";
      btn.setAttribute("aria-pressed", "false");
      btn.dataset.id = n.id;
      var isPublic = exposureTagFor(n.id) === "public";
      btn.innerHTML =
        '<span class="ep__route">' +
          '<span class="ep__method">' + esc(a.method || "ANY") + '</span>' +
          '<span class="ep__path">' + esc(a.path || n.name || n.id) + '</span>' +
          (isPublic ? '<span class="ep__public">PUBLIC</span>' : '') +
        '</span>' +
        '<span class="ep__vuln">' +
          '<span class="ep__dep">' + esc(w.dep.name || w.dep.id) + '</span>' +
          '<span class="vv ' + (w.tainted ? "vv--exploit" : "vv--reach") + '">' + esc(w.verdict) + '</span>' +
        '</span>';
      btn.addEventListener("click", function () {
        if (selectedEp === n.id) { resetView(); } else { lightTrace(n.id, false); }
      });
      li.appendChild(btn);
      el.eplist.appendChild(li);
    });
  }

  function updateEpButtons(epId) {
    Array.prototype.forEach.call(el.eplist.querySelectorAll(".ep"), function (b) {
      var on = b.dataset.id === epId;
      b.setAttribute("aria-pressed", on ? "true" : "false");
      // Open the enclosing prefix group so the active route is visible.
      if (on) {
        var grp = b.closest("details.epgroup");
        if (grp) grp.open = true;
      }
    });
  }

  function renderReachInitial() {
    if (!el.reachBody) return; // reach panel removed in the minimal view
    el.reachBody.innerHTML =
      '<p class="panel__empty">No entry point selected. Pick one above to trace what it reaches.</p>';
  }

  function renderReachEmptyFocus(node) {
    if (!el.reachBody) return;
    el.reachBody.innerHTML =
      '<p class="reach-none">Focusing <b>' + esc(node.data("name")) +
      '</b> and its direct neighbors. Select an entry point to trace reachability.</p>';
  }

  function renderReach(epId, res) {
    if (!el.reachBody) return; // reach panel removed in the minimal view
    var ep = model.index[epId];
    var label = esc(labelFor(ep));
    var html = '<p class="reach-head">Entry point <b>' + label + '</b> reaches ' +
      res.deps.length + ' ' + (res.deps.length === 1 ? "dependency" : "dependencies") + '.</p>';
    if (!res.deps.length) {
      html += '<p class="reach-none">This route resolves no calls into a declared dependency. ' +
        'Its handler may use only intra-repo code, or calls could not be resolved.</p>';
    } else {
      html += '<ul class="deplist">';
      res.deps.forEach(function (d) {
        var a = d.attrs || {};
        html += '<li class="dep"><div class="dep__name">' + esc(d.name || d.id) + '</div>' +
          '<div class="dep__meta">' +
          (a.ecosystem ? '<span class="dep__eco">' + esc(a.ecosystem) + '</span>' : '') +
          (a.version ? '<span class="dep__ver">' + esc(a.version) + '</span>' : '') +
          '</div></li>';
      });
      html += '</ul>';
    }
    el.reachBody.innerHTML = html;
  }

  // The reach panel when a dependency is selected: it reports the reverse set —
  // how many entry points and nodes reach this dependency — and lists the routes.
  function renderReachReverse(depId, res) {
    if (!el.reachBody) return; // reach panel removed in the minimal view
    var dep = model.index[depId];
    var name = esc(dep ? (dep.name || dep.id) : depId);
    var eps = res.entrypoints || [];
    var nodeCount = Object.keys(res.nodes).length - 1; // minus the dep itself
    var html = '<p class="reach-head">Dependency <b>' + name + '</b> is reached by ' +
      eps.length + ' entry point' + (eps.length === 1 ? "" : "s") +
      ' across ' + nodeCount + ' node' + (nodeCount === 1 ? "" : "s") + '.</p>';
    if (!eps.length) {
      html += '<p class="reach-none">No public route reaches this dependency through resolved calls. ' +
        'Its reaching subgraph (if any) is internal code only.</p>';
    } else {
      html += '<ul class="deplist">';
      eps.forEach(function (ep) {
        var a = ep.attrs || {};
        html += '<li class="dep"><div class="dep__name">' +
          esc((a.method ? a.method + " " : "") + (a.path || ep.name || ep.id)) + '</div></li>';
      });
      html += '</ul>';
    }
    el.reachBody.innerHTML = html;
  }

  /* ---------------------------------------------------------------- vulnerabilities */
  var SEV_RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };

  // Deterministic escalation ladder (NOT advisory): taint beats symbol_match
  // beats bare reachability. Picks the finding highest on the ladder as the
  // representative for a dependency's escalation panel.
  var SYMBOL_RANK = { confirmed: 3, package_reachable: 2, no_path: 1 };
  var TAINT_RANK = { tainted: 1, not_proven: 0 };
  function escalationRank(f) {
    return (TAINT_RANK[f.taint] || 0) * 100 +
      (SYMBOL_RANK[f.symbol_match] || 0) * 10 +
      (f.reachable ? 1 : 0);
  }

  // Build a per-dependency roll-up from the ranked findings so the graph and
  // the panel agree on what is vulnerable, reachable and actively exploited.
  function computeVulnState() {
    vulnByDep = {};
    findings.forEach(function (f) {
      var id = f.dependency_id;
      if (!id) return;
      var vs = vulnByDep[id] || (vulnByDep[id] = {
        findings: [], kev: false, reachable: false, worst: 0, entrypoints: [],
        symbolConfirmed: false, tainted: false, escFinding: null, escRank: -1,
        taintEntrypoints: []
      });
      vs.findings.push(f);
      if (f.kev) vs.kev = true;
      if (f.reachable) vs.reachable = true;
      // Deterministic signals: did a resolved path reach the vulnerable function
      // (symbol_match), and does attacker input prove to reach the call (taint)?
      if (f.symbol_match === "confirmed") vs.symbolConfirmed = true;
      if (f.taint === "tainted") vs.tainted = true;
      // Retain the entry-point label each PROVEN taint path runs through, so a
      // route only reads EXPLOITABLE when the taint actually flows through IT (not
      // merely because the dep is tainted via some other route). Labels here match
      // labelFor() for an entry point ("METHOD /path").
      if (f.taint === "tainted" && f.taint_evidence && f.taint_evidence.entrypoint) {
        var te = f.taint_evidence.entrypoint;
        if (vs.taintEntrypoints.indexOf(te) < 0) vs.taintEntrypoints.push(te);
      }
      var escR = escalationRank(f);
      if (escR > vs.escRank) { vs.escFinding = f; vs.escRank = escR; }
      var rank = SEV_RANK[(f.severity || "").toUpperCase()] || 0;
      if (rank > vs.worst) vs.worst = rank;
      (f.reachable_entrypoints || []).forEach(function (ep) {
        if (vs.entrypoints.indexOf(ep) < 0) vs.entrypoints.push(ep);
      });
    });

    // Index the advisory exploitability triage by dependency, and mark the dep
    // with its strongest verdict so the finding list can surface and rank it.
    triageByDep = {};
    triage.forEach(function (t) {
      var id = t.dependency_id;
      if (!id) return;
      (triageByDep[id] || (triageByDep[id] = [])).push(t);
      var vs = vulnByDep[id];
      if (vs && t.affected === "affected") vs.triageAffected = true;
    });

    // Index the advisory dynamic-usage investigation by dependency (one per dep;
    // only for vulnerable deps with no statically-resolved call into them).
    usageByDep = {};
    usage.forEach(function (u) {
      if (u && u.dependency_id) usageByDep[u.dependency_id] = u;
    });
  }

  // The triage entry matching a finding's CVE within its dependency, if any:
  // a triage row covers a (dependency, CVE) pair via its `cve`/`cves` fields.
  function triageForFinding(f) {
    var rows = triageByDep[f.dependency_id];
    if (!rows || !rows.length) return null;
    var ids = (f.cve_ids && f.cve_ids.length) ? f.cve_ids.slice() : [];
    if (f.vuln_id) ids.push(f.vuln_id);
    for (var i = 0; i < rows.length; i++) {
      var t = rows[i];
      var tc = (t.cves && t.cves.length) ? t.cves.slice() : [];
      if (t.cve) tc.push(t.cve);
      if (t.vuln_id) tc.push(t.vuln_id);
      for (var j = 0; j < tc.length; j++) {
        if (ids.indexOf(tc[j]) >= 0) return t;
      }
    }
    return null;
  }

  // Advisory-triage verdict -> { label, cls } for a compact badge.
  var TRIAGE_META = {
    affected:          { label: "exploitable",   cls: "tri tri--affected" },
    likely_unaffected: { label: "likely safe",   cls: "tri tri--safe" },
    uncertain:         { label: "triage: unsure", cls: "tri tri--uncertain" }
  };
  function triageBadge(t) {
    if (!t || !t.affected) return "";
    var m = TRIAGE_META[t.affected] || TRIAGE_META.uncertain;
    return '<span class="' + m.cls + '" title="Advisory exploitability triage">' +
      esc(m.label) + '</span>';
  }
  var TRIAGE_RANK = { affected: 3, uncertain: 2, likely_unaffected: 1 };
  function triageRank(v) { return TRIAGE_RANK[v] || 0; }

  function sevTag(f) {
    var label = (f.severity || "UNKNOWN").toUpperCase();
    var cls = "tag tag--sev";
    if (label === "CRITICAL") cls += " tag--sev-critical";
    var txt = label;
    if (f.cvss_score != null) txt += " " + Number(f.cvss_score).toFixed(1);
    return '<span class="' + cls + '">' + esc(txt) + '</span>';
  }

  function renderVulns() {
    if (!el.vulnBody || !el.vulnNote) return; // findings panel removed in the minimal view
    // Plain graph (no bundle): honest structure-only note, no finding list.
    if (!bundleMeta) {
      el.vulnNote.textContent = "Structure only — load an audit bundle to see findings.";
      el.vulnBody.innerHTML = "";
      return;
    }

    // Degraded bundle: offline run or the vuln database was unreachable.
    if (bundleMeta.offline || bundleMeta.network_ok === false) {
      el.vulnNote.textContent = "Vulnerability data was not available for this scan.";
      var why = (bundleMeta.notices && bundleMeta.notices.length)
        ? bundleMeta.notices[0]
        : (bundleMeta.offline
            ? "Scanned offline (--offline), so no advisory database was queried."
            : "The advisory database could not be reached.");
      el.vulnBody.innerHTML =
        '<p class="vuln-note vuln-note--warn">' + esc(why) +
        ' This is not a clean bill of health — the graph and reachability still apply.</p>';
      return;
    }

    if (!findings.length) {
      el.vulnNote.textContent = "Ranked by exploitation and reachability.";
      el.vulnBody.innerHTML =
        '<p class="vuln-note">No known vulnerabilities matched the resolved dependencies.</p>';
      return;
    }

    var reachN = findings.filter(function (f) { return f.reachable; }).length;
    var depGroups = groupFindingsByDep();
    el.vulnNote.innerHTML = (reachN
      ? '<b>' + reachN + '</b> of ' + findings.length + ' findings reach a public route'
      : 'None of the ' + findings.length + ' findings reach a public route') +
      ' · ' + depGroups.length + ' affected ' + (depGroups.length === 1 ? "package" : "packages") + '.';

    // One collapsed row per vulnerable DEPENDENCY, risk-sorted. Expanding a row
    // reveals its individual CVEs in place — so the default is a handful of
    // packages, not one row per CVE.
    var html = '<ul class="deplist deplist--vuln">';
    depGroups.forEach(function (g) {
      html += '<li>' + depGroupRowHtml(g) + '</li>';
    });
    html += '</ul>';
    el.vulnBody.innerHTML = html;
  }

  // Roll findings up to one entry per dependency, ranked by risk:
  // reachable first, then actively exploited (KEV), then severity, then EPSS.
  function groupFindingsByDep() {
    var groups = [];
    Object.keys(vulnByDep).forEach(function (id) {
      var vs = vulnByDep[id];
      var f0 = vs.findings[0] || {};
      var maxEpss = 0;
      vs.findings.forEach(function (f) { if (f.epss != null && f.epss > maxEpss) maxEpss = f.epss; });
      groups.push({
        id: id, name: f0.dependency_name || id, version: f0.version || "",
        ecosystem: f0.ecosystem || "", findings: vs.findings,
        reachable: vs.reachable, kev: vs.kev, worst: vs.worst, maxEpss: maxEpss,
        triageAffected: !!vs.triageAffected,
        taintTainted: !!vs.tainted, symbolConfirmed: !!vs.symbolConfirmed
      });
    });
    groups.sort(function (a, b) {
      return ((b.taintTainted ? 1 : 0) - (a.taintTainted ? 1 : 0)) ||
        ((b.symbolConfirmed ? 1 : 0) - (a.symbolConfirmed ? 1 : 0)) ||
        ((b.triageAffected ? 1 : 0) - (a.triageAffected ? 1 : 0)) ||
        (b.reachable - a.reachable) || (b.kev - a.kev) ||
        (b.worst - a.worst) || (b.maxEpss - a.maxEpss) ||
        a.name.localeCompare(b.name);
    });
    return groups;
  }

  // The worst-severity label across a group's findings, for the summary row tag.
  function worstSevLabel(g) {
    var best = "", bestRank = -1;
    g.findings.forEach(function (f) {
      var r = SEV_RANK[(f.severity || "").toUpperCase()] || 0;
      if (r > bestRank) { bestRank = r; best = (f.severity || "").toUpperCase(); }
    });
    return best || "UNKNOWN";
  }

  // A dependency summary row (a <details>): name + version, CVE count, top
  // severity, and REACHABLE / KEV badges. The body lists its individual CVEs.
  function depGroupRowHtml(g) {
    var n = g.findings.length;
    var sev = worstSevLabel(g);
    var sevCls = "tag tag--sev" + (sev === "CRITICAL" ? " tag--sev-critical" : "");

    var sum = '<summary class="depgroup__sum">' +
      '<span class="disc__chev" aria-hidden="true"></span>' +
      '<span class="depgroup__name">' + esc(g.name) +
        (g.version ? ' <span class="depgroup__ver">' + esc(g.version) + '</span>' : '') + '</span>' +
      '<span class="depgroup__tags">' +
        '<span class="depgroup__count">' + n + ' CVE' + (n === 1 ? "" : "s") + '</span>' +
        '<span class="' + sevCls + '">' + esc(sev) + '</span>' +
        (g.reachable ? '<span class="tag tag--reach">reachable</span>' : '') +
        (g.symbolConfirmed ? '<span class="sym sym--confirmed">function confirmed</span>' : '') +
        (g.taintTainted ? '<span class="taint taint--tainted">tainted</span>' : '') +
        (g.kev ? '<span class="tag tag--kev">KEV</span>' : '') +
        (g.triageAffected ? '<span class="tri tri--affected">exploitable</span>' : '') +
      '</span></summary>';

    var body = '<ul class="cvelist">';
    g.findings.slice().sort(function (a, b) {
      return (b.reachable - a.reachable) ||
        ((SEV_RANK[(b.severity || "").toUpperCase()] || 0) - (SEV_RANK[(a.severity || "").toUpperCase()] || 0)) ||
        ((b.epss || 0) - (a.epss || 0));
    }).forEach(function (f) {
      var cve = (f.cve_ids && f.cve_ids.length) ? f.cve_ids.join(", ") : (f.vuln_id || "");
      var t = triageForFinding(f);
      body += '<li class="cve' + (f.reachable ? " cve--reachable" : "") + '"><div class="cve__id">' + esc(cve) + '</div>' +
        (f.summary ? '<div class="cve__sum">' + esc(f.summary) + '</div>' : "") +
        '<div class="vuln__tags">' + sevTag(f) +
        (f.kev ? '<span class="tag tag--kev">KEV</span>' : "") +
        (f.reachable ? '<span class="tag tag--reach">reachable</span>' : "") +
        (f.symbol_match === "confirmed" ? '<span class="sym sym--confirmed">confirmed</span>' : "") +
        (f.taint === "tainted" ? '<span class="taint taint--tainted">tainted</span>' : "") +
        triageBadge(t) +
        '</div>' +
        (t && t.rationale ? '<div class="cve__triage"><span class="cve__triage-h">Exploitability</span> ' + esc(t.rationale) + '</div>' : "") +
        (f.fixed_versions && f.fixed_versions.length ? '<div class="cve__fix">Fixed in <b>' + esc(f.fixed_versions.join(", ")) + '</b></div>' : "") +
        (f.reachable && f.example_path && f.example_path.length
          ? '<div class="vuln__path"><span class="path-steps">' + esc(f.example_path.join(" → ")) + '</span></div>' : "") +
        '</li>';
    });
    body += '</ul>';

    return '<details class="depgroup' + (g.reachable ? " depgroup--reachable" : "") + '">' +
      sum + '<div class="depgroup__body">' + body + '</div></details>';
  }

  function verdictText(f) {
    if (f.verdict === "potentially_reachable") {
      return "Potentially reachable: no resolved path reaches it, but unresolved calls could.";
    }
    if (f.verdict === "unreachable") {
      return "Not reachable from a public entry point (call graph fully resolved).";
    }
    return "Not reachable from a public entry point.";
  }

  /* ---------------------------------------------------------------- detail panel */
  var CTX_ORDER = ["data_store", "external_service", "authentication", "data_handling", "other"];
  var CTX_LABEL = {
    data_store: "Data stores", external_service: "External services",
    authentication: "Authentication", data_handling: "Data handling", other: "Other context"
  };
  var KIND_EYEBROW = {
    entrypoint: "Entry point", dependency: "Dependency", function: "Function",
    module: "Module", file: "File", doc: "Document"
  };

  function uniq(arr) { var out = []; arr.forEach(function (x) { if (out.indexOf(x) < 0) out.push(x); }); return out; }
  function moreBtn() { return '<button type="button" class="more" data-clamp>Show more</button>'; }

  function isRiskExposure(e) { return /internet|public|external/i.test(String(e)); }
  function isRiskAuth(a) { return /none|no\s*auth|unauth|anonymous/i.test(String(a)); }
  function badge(k, v, risk) {
    return '<span class="badge ' + (risk ? "badge--risk" : "badge--ok") + '">' +
      '<span class="badge__k">' + esc(k) + '</span>' + esc(v) + '</span>';
  }

  // Mark the node whose datasheet is open (bright halo on the canvas).
  function markSelected(id) {
    selectedNodeId = id;
    if (!cy) return;
    cy.nodes().removeClass("selected");
    if (id) { var n = cy.getElementById(id); if (n && n.length) n.addClass("selected"); }
  }

  // Open or collapse the detail drawer. The drawer OVERLAYS the canvas (it no
  // longer takes a grid column), so opening it never resizes, re-fits or
  // re-zooms the graph — which is what used to throw the viewport around and
  // leave edges briefly misaligned. We only slide the graph sideways by roughly
  // the drawer's width so the right-hand dependency column stays visible beside
  // it: a pure pan, no zoom change and no cy.resize().
  function setDrawer(open) {
    if (!el.layout) return;
    var was = el.layout.classList.contains("has-detail");
    el.layout.classList.toggle("has-detail", open);
    if (was !== open) panForDrawer(open);
  }

  function panForDrawer(open) {
    if (!cy) return;
    // On narrow screens the drawer stacks below the canvas (static flow), so a
    // horizontal pan would be wrong — leave the viewport alone.
    if (window.matchMedia && window.matchMedia("(max-width: 860px)").matches) return;
    var w = el.detail ? el.detail.getBoundingClientRect().width : 0;
    var shift = (w || 336) - 24;            // drawer width minus a small gutter
    var dx = open ? -shift : shift;
    if (REDUCED) cy.panBy({ x: dx, y: 0 });
    else cy.animate({ panBy: { x: dx, y: 0 } }, { duration: 160, easing: "ease-out" });
  }

  // Assessments whose reaching_entrypoints include this endpoint's label
  // ("METHOD /path"), which is exactly how the bundle records them.
  function assessmentsForEpLabel(label) {
    var want = String(label).trim();
    return assessments.filter(function (a) {
      return (a.reaching_entrypoints || []).some(function (x) { return String(x).trim() === want; });
    });
  }

  function docRefHtml(dref) {
    return '<div class="docref"><span class="docref__src">' + esc(dref.source || "doc") + '</span>' +
      '<div class="snip__text clamp">' + esc(String(dref.snippet || "").trim()) + '</div>' + moreBtn() + '</div>';
  }

  function detailHead(kind, title) {
    var color = KIND_COLOR[kind] || "#4E7493";
    return '<div class="detail__head" style="--kind:' + color + '">' +
      '<span class="detail__kind">' + esc(KIND_EYEBROW[kind] || kind) + '</span>' +
      '<button type="button" class="detail__close" id="detail-close" aria-label="Close details">×</button>' +
      '<h1 class="detail__title">' + esc(title) + '</h1></div>';
  }

  // A consistent disclosure: a real <details>/<summary> (keyboard-accessible,
  // its own aria-expanded) styled as a compact row with a rotating chevron.
  function disclosure(label, bodyHtml, open) {
    return '<details class="disc"' + (open ? " open" : "") + '>' +
      '<summary class="disc__sum"><span class="disc__chev" aria-hidden="true"></span>' +
      '<span class="disc__label">' + esc(label) + '</span></summary>' +
      '<div class="disc__body">' + bodyHtml + '</div></details>';
  }

  // The docs this endpoint/function was cited in — rendered as text snippets.
  function docsHtml(docs) { return docs.map(docRefHtml).join(""); }

  // Every source the assessment cites: an explicit `sources` list if present,
  // otherwise the distinct sources of its context items (README.md, openapi…).
  function sourcesFor(ms) {
    var out = [];
    ms.forEach(function (a) {
      (a.sources || []).forEach(function (s) { if (s && out.indexOf(s) < 0) out.push(s); });
      (a.context || []).forEach(function (c) { if (c.source && out.indexOf(c.source) < 0) out.push(c.source); });
    });
    return out;
  }

  // PRIMARY block: the integrated advisory summary paragraph + a compact Sources
  // line + the advisory/provenance marking. This is all that shows by default.
  function assessmentSummaryHtml(ms) {
    var summaries = uniq(ms.map(function (a) { return a.summary; }).filter(Boolean))
      .sort(function (a, b) { return b.length - a.length; });
    var lead = summaries[0] || "";
    var provs = uniq(ms.map(function (a) { return a.provenance; }).filter(Boolean));
    var srcs = sourcesFor(ms);

    var html = '<section class="dsec"><h2 class="dsec__h">Assessment <span class="advisory-flag">Advisory' +
      provs.map(function (p) { return ' · ' + esc(p); }).join("") + '</span></h2>';
    html += '<div class="summary-card">';
    html += '<p class="summary-lead">' + esc(lead) + '</p>';
    if (srcs.length) {
      html += '<p class="sources-line"><span class="sources-line__k">Sources</span>' +
        srcs.map(esc).join(", ") + '</p>';
    }
    html += '<p class="advisory-foot">An exposure assessment, not the deterministic reachability verdict — it adds context, never changes whether a path exists.</p>';
    html += '</div></section>';
    return html;
  }

  // The depth, for the "Details & sources" disclosure: exposure/auth badges, the
  // rationale, the CVEs covered, the cited context groups and the doc excerpts.
  function assessmentDetailsHtml(ms, docs) {
    var exposures = uniq(ms.map(function (a) { return a.exposure; }).filter(Boolean));
    var auths = uniq(ms.map(function (a) { return a.authentication; }).filter(Boolean));
    var rationales = uniq(ms.map(function (a) { return a.rationale; }).filter(Boolean));
    var cves = uniq(ms.map(function (a) { return a.cve || a.vuln_id; }).filter(Boolean));

    var seen = {}, byCat = {};
    ms.forEach(function (a) {
      (a.context || []).forEach(function (c) {
        var cat = c.category || "other";
        var key = cat + "|" + (c.detail || "") + "|" + (c.source || "") + "|" + (c.snippet || "");
        if (seen[key]) return;
        seen[key] = true;
        (byCat[cat] || (byCat[cat] = [])).push(c);
      });
    });

    var html = "";
    if (exposures.length || auths.length) {
      html += '<div class="badges">';
      exposures.forEach(function (e) { html += badge("Exposure", e, isRiskExposure(e)); });
      auths.forEach(function (a) { html += badge("Auth", a, isRiskAuth(a)); });
      html += '</div>';
    }
    if (rationales.length) {
      rationales.forEach(function (r) { html += '<p class="prose prose--quote clamp">' + esc(r) + '</p>' + moreBtn(); });
    }
    if (cves.length) html += '<p class="dim-note">Covers ' + cves.map(esc).join(", ") + '</p>';

    var cats = CTX_ORDER.slice();
    Object.keys(byCat).forEach(function (k) { if (cats.indexOf(k) < 0) cats.push(k); });
    cats.forEach(function (cat) {
      var items = byCat[cat];
      if (!items || !items.length) return;
      html += '<div class="ctxgroup"><div class="ctxgroup__h">' + esc(CTX_LABEL[cat] || cat) +
        ' <span class="dsec__count">' + items.length + '</span></div><ul class="ctxlist">';
      items.forEach(function (c) {
        html += '<li class="ctxitem"><div class="ctxitem__detail">' + esc(c.detail || "") + '</div>' +
          (c.access ? '<div class="ctxitem__access">' + esc(c.access) + '</div>' : '') +
          '<div class="snip"><span class="snip__src">' + esc(c.source || "doc") + '</span>' +
          '<div class="snip__text clamp">' + esc(String(c.snippet || "").trim()) + '</div>' + moreBtn() +
          '</div></li>';
      });
      html += '</ul></div>';
    });

    if (docs && docs.length) {
      html += '<div class="ctxgroup"><div class="ctxgroup__h">Mentioned in docs ' +
        '<span class="dsec__count">' + docs.length + '</span></div>' + docsHtml(docs) + '</div>';
    }
    return html;
  }

  /* ------------------------------------------------------------- minimal pop-out
     The right pop-out is intentionally HIGH-LEVEL ONLY: a verdict badge, one
     plain-language sentence, the fix (if any), and an "Ask the agent" button that
     bridges to the chat agent with a grounded question. No paths, no snippets, no
     data flow, no technical fields — all of that now lives in the chat agent. */

  // The chat bridge: the dashboard and chat page are served from the same origin
  // (the chat page is chat.html); a ?q= question pre-fills + auto-sends in chat.js.
  function chatLink(question) { return "chat.html?q=" + encodeURIComponent(String(question)); }
  function askBtnHtml(question) {
    return '<a class="askbtn" href="' + esc(chatLink(question)) + '">' +
      'Ask the agent <span aria-hidden="true">&rarr;</span></a>';
  }
  function popBadge(kind, text) {
    return '<span class="pop__badge pop__badge--' + kind + '">' + esc(text) + '</span>';
  }
  var _popRepo = function () { return currentRepo || "this project"; };

  // Fix sentence fragment (HTML) from the first finding that names a fixed version.
  function fixFragment(fs, name) {
    for (var i = 0; i < fs.length; i++) {
      var v = fs[i] && fs[i].fixed_versions;
      if (v && v.length) return 'upgrade <b>' + esc(name) + '</b> to ' + esc(v[0]) + '.';
    }
    return "";
  }
  // The route attacker input flows through for a tainted finding, if recorded.
  function taintRoute(fs) {
    for (var i = 0; i < fs.length; i++) {
      var f = fs[i];
      if (f.taint === "tainted" && f.taint_evidence && f.taint_evidence.entrypoint) {
        return f.taint_evidence.entrypoint;
      }
    }
    return "";
  }
  // The first entry-point label on a likely-reachable dep's inferred `via` path.
  function likelyRoute(l) {
    var via = (l && Array.isArray(l.via)) ? l.via : [];
    for (var i = 0; i < via.length; i++) {
      var m = model.index[via[i]];
      if (m && m.kind === "entrypoint") return labelFor(m);
    }
    return "";
  }

  function detailEntrypoint(n) {
    var a = n.attrs || {};
    var label = labelFor(n);
    var route = (a.method ? a.method + " " : "") + (a.path || n.name || n.id);
    var repo = _popRepo();
    var isPublic = exposureTagFor(n.id) === "public";
    var dsev = dangerSevFor(n.id);
    var afs = epFindings(n.id);
    var worst = worstReachedVuln(n.id);
    var html = detailHead("entrypoint", label) + '<div class="pop">';

    if (dsev && afs.length) {
      // Lead with the AI code-level hypothesis — distinct magenta badge, clearly
      // unverified. NEVER a proven verdict.
      var topF = afs.slice().sort(cmpFinding)[0] || {};
      var klass = topF.vuln_class || topF.title || "possible vulnerability";
      html += popBadge("danger", "⚠ Code-level risk · AI (unverified)");
      if (topF.title) html += '<p class="pop__title">' + esc(String(topF.title)) + '</p>';
      html += '<p class="pop__line">An AI pen-tester flagged a candidate vulnerability in this ' +
        'route’s own code. This is an <strong>unverified AI hypothesis</strong>, not a proven finding.</p>';
      if (isPublic) html += '<p class="pop__line">This route is <strong>internet-facing</strong>.</p>';
      html += askBtnHtml("Explain the code-level " + klass + " risk on " + route + " in " + repo);
    } else if (worst) {
      html += popBadge(worst.tainted ? "exploit" : "reach",
        worst.tainted ? "Exploitable" : "Reachable vulnerability");
      html += '<p class="pop__line">This route reaches <b>' + esc(worst.dep.name || worst.dep.id) + '</b>' +
        (worst.tainted
          ? ', and attacker input provably reaches the vulnerable call.'
          : ', which has a known vulnerability — reachable, but not proven exploitable.') + '</p>';
      if (isPublic) html += '<p class="pop__line">This route is <strong>internet-facing</strong>.</p>';
      html += askBtnHtml("Explain how " + route + " reaches " + (worst.dep.name || worst.dep.id) +
        " in " + repo + " and how to fix it");
    } else {
      html += popBadge(isPublic ? "public" : "neutral", isPublic ? "Public" : "Entry point");
      html += '<p class="pop__line">' +
        (isPublic ? 'This route is <strong>internet-facing</strong>. ' : '') +
        'No known-vulnerable dependency is reachable from this route.</p>';
      html += askBtnHtml("What is the attack surface of " + route + " in " + repo + "?");
    }
    return html + '</div>';
  }

  function detailFunction(n) {
    var name = n.name || n.id;
    var repo = _popRepo();
    var html = detailHead("function", name) + '<div class="pop">';
    html += popBadge("neutral", "Function");
    html += '<p class="pop__line">A function in the application code' +
      (selectedEp ? ', on the current trace' : '') +
      '. Ask the agent what it does and whether it is security-relevant.</p>';
    html += askBtnHtml("What does the function " + name + " do in " + repo +
      ", and is it security-relevant?");
    return html + '</div>';
  }

  /* ---------------------------------------------------------------- AI attack analysis */
  // Lead finding for a dependency: tainted first, else the highest-severity
  // reachable finding, else the highest-severity finding. null when none.
  function leadFinding(fs) {
    if (!fs || !fs.length) return null;
    function sev(f) { return SEV_RANK[(f.severity || "").toUpperCase()] || 0; }
    function best(list) {
      return list.reduce(function (b, f) { return !b || sev(f) > sev(b) ? f : b; }, null);
    }
    var tainted = fs.filter(function (f) { return f.taint === "tainted"; });
    if (tainted.length) return best(tainted);
    var reach = fs.filter(function (f) { return f.reachable === true; });
    return best(reach.length ? reach : fs);
  }

  function aiBadgeHtml(model) {
    return '<span class="ai-badge"><span class="ai-badge__mark" aria-hidden="true"></span>' +
      'AI analysis · ' + esc(model || "Meta Muse") + '</span>';
  }
  function aiLoadingHtml() {
    return '<p class="ai-loading" role="status">' + aiBadgeHtml("Meta Muse") +
      '<span class="ai-loading__txt">Analyzing with Meta Muse<span class="ai-dots" aria-hidden="true">…</span></span></p>';
  }
  function aiNoteHtml(msg) { return '<p class="dim-note ai-note">' + esc(msg) + '</p>'; }
  // Untrusted model text -> safe HTML. The model replies in Markdown; VScanMd
  // (md.js) escapes first, then applies an allowlisted subset. If md.js failed to
  // load we fall back to escaped paragraphs (single newlines become <br>).
  function aiParasHtml(text, cls) {
    text = String(text == null ? "" : text);
    if (window.VScanMd && typeof window.VScanMd.mdToHtml === "function") {
      return '<div class="md ' + cls + '">' + window.VScanMd.mdToHtml(text) + '</div>';
    }
    return text.split(/\n\s*\n/).map(function (para) {
      para = para.trim();
      return para ? '<p class="' + cls + '">' + esc(para).replace(/\n/g, "<br>") + '</p>' : "";
    }).join("");
  }
  // Deterministic (static-analysis) verdict -> label + modifier class. Lookup map
  // only; an unknown/missing verdict yields no badge (never guess).
  var AI_VERDICTS = {
    exploitable: { label: "EXPLOITABLE", cls: "ai-verdict--exploit" },
    reachable:   { label: "REACHABLE \u00B7 NOT PROVEN EXPLOITABLE", cls: "ai-verdict--reach" },
    not_reached: { label: "NOT REACHED", cls: "ai-verdict--safe" }
  };
  function aiVerdictHtml(verdict) {
    var v = typeof verdict === "string" && Object.prototype.hasOwnProperty.call(AI_VERDICTS, verdict)
      ? AI_VERDICTS[verdict] : null;
    if (!v) return "";
    return '<div class="ai-verdict ' + v.cls + '"><span class="ai-verdict__k">VScan verdict</span>' +
      '<span class="ai-verdict__v">' + esc(v.label) + '</span></div>';
  }
  function aiResultHtml(d) {
    var live = d.provenance === "llm";
    return aiVerdictHtml(d.verdict) + '<div class="ai-head">' + aiBadgeHtml(d.model) +
      '<span class="ai-prov ' + (live ? "ai-prov--live" : "ai-prov--offline") + '">' +
      (live ? "live model" : "offline analysis") + '</span></div>' +
      aiParasHtml(d.narrative, "prose ai-narr") +
      (d.remediation && String(d.remediation).trim()
        ? '<div class="ai-fix"><span class="ai-fix__k">Fix</span>' + aiParasHtml(d.remediation, "prose ai-fix__v") + '</div>'
        : "");
  }

  // Fetch the analysis for the section just rendered into the drawer. Stale
  // responses are dropped two ways: the previous request is aborted, and a result
  // is only painted if its section is still the live one and still in the DOM.
  var aiCtl = null, aiSeq = 0;
  function loadAiAnalysis(sec) {
    if (aiCtl) { try { aiCtl.abort(); } catch (e) {} aiCtl = null; }
    if (!sec) return;
    var mySeq = ++aiSeq;
    var body = sec.querySelector(".ai-body");
    if (!body) return;
    var ctl = (typeof AbortController === "function") ? new AbortController() : null;
    aiCtl = ctl;
    function live() { return mySeq === aiSeq && document.body.contains(sec); }
    function show(h) { if (live()) body.innerHTML = h; }
    if (typeof fetch !== "function") { show(aiNoteHtml("AI analysis unavailable.")); return; }
    // The current view's repo rides the query string so the backend explains THIS
    // scan's finding, not whichever one is primary server-side (otherwise a
    // non-primary view gets a foreign verdict + foreign file paths). Views with no
    // live repo (file loads) have no live analysis —
    // skip the fetch rather than hit the primary by omission (mirrors enrichment).
    var repo = currentRepo;
    if (!repo) { show(aiNoteHtml("Live AI analysis isn't available for this scan.")); return; }
    var opts = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dependency_id: sec.getAttribute("data-ai-dep"),
        vuln_id: sec.getAttribute("data-ai-vuln")
      })
    };
    if (ctl) opts.signal = ctl.signal;
    fetch("/api/explain?repo=" + encodeURIComponent(repo), opts).then(function (r) {
      if (r.status === 404) { show(aiNoteHtml("Live AI analysis isn't available for this scan.")); return null; }
      if (r.status === 503) { show(aiNoteHtml("Scan still warming up — try again in a moment.")); return null; }
      if (!r.ok) throw new Error("http " + r.status);
      return r.json();
    }).then(function (d) {
      if (!d) return;
      // Degraded response (a `note`, no narrative): surface the note instead of a
      // generic "unavailable" so warming/degraded never reads as a clean result.
      if (!d.narrative) {
        if (d.note) { show(aiNoteHtml(String(d.note))); return; }
        throw new Error("empty");
      }
      show(aiResultHtml(d));
    }).catch(function (e) {
      if (e && e.name === "AbortError") return;
      show(aiNoteHtml("AI analysis unavailable."));
    });
  }

  // ADVISORY "Likely reachable (inferred)" drawer section (Phase 2). Shown for a
  // dependency the AI flagged in `likely_reachable`: static analysis resolved no
  // path to it, but the AI inferred one. It renders the inferred `via` path as
  // readable labels and the contributing inferred edges' symbol + rationale +
  // source citations. It states plainly that this is a LEAD — it never makes the
  // finding proven-reachable or exploitable and never changes the verdict above.
  // Returns "" when the dep is not in likely_reachable (fully additive). All
  // server text is escaped via esc().
  function detailDependency(n) {
    var a = n.attrs || {};
    var name = n.name || n.id;
    var repo = _popRepo();
    var vs = vulnByDep[n.id];
    var depFindings = findings.filter(function (f) { return f.dependency_id === n.id; });
    var lead = leadFinding(depFindings);
    var cve = lead ? ((lead.cve_ids && lead.cve_ids.length) ? lead.cve_ids.join(", ") : (lead.vuln_id || "")) : "";
    var likely = likelyByDep[n.id];
    var html = detailHead("dependency", name + (a.version ? " " + a.version : "")) + '<div class="pop">';

    if (vs && vs.tainted) {
      var route = taintRoute(depFindings) || vs.entrypoints[0] || "a public route";
      html += popBadge("exploit", "Exploitable");
      html += '<p class="pop__line">Attacker input reaches the vulnerable call via <b>' + esc(route) + '</b>.</p>';
    } else if (vs && vs.reachable) {
      var r2 = vs.entrypoints.length ? vs.entrypoints.join(", ") : "a public route";
      html += popBadge("reach", "Reachable");
      html += '<p class="pop__line"><b>' + esc(name) + '</b> is reachable from ' + esc(r2) +
        ', but we did not prove attacker input reaches the flaw — reachable, not proven exploitable.</p>';
    } else if (likely) {
      var lr = likelyRoute(likely);
      html += popBadge("likely", "Likely reachable · AI-inferred");
      html += '<p class="pop__line">Static analysis didn’t resolve a path, but the AI inferred one' +
        (lr ? ' via <b>' + esc(lr) + '</b>' : '') + ' — advisory, not proven.</p>';
    } else if (vs) {
      html += popBadge("notreached", "Not reached");
      html += '<p class="pop__line">A known CVE exists, but no public route reaches <b>' + esc(name) +
        '</b>, so it is not exploitable from the outside.</p>';
    } else {
      html += popBadge("neutral", "No known vulnerability");
      html += '<p class="pop__line">No known vulnerability matched <b>' + esc(name) +
        (a.version ? " " + esc(a.version) : "") + '</b>.</p>';
      html += askBtnHtml("Tell me about the dependency " + name + " in " + repo);
      return html + '</div>';
    }

    var fix = fixFragment(depFindings, name);
    if (fix) html += '<p class="pop__fix">Fix: ' + fix + '</p>';
    if (likely && !(vs && (vs.tainted || vs.reachable))) {
      html += '<p class="pop__advisory">AI-inferred reachability is advisory — it does not change the ' +
        'verdict or the funnel counts.</p>';
    }
    html += askBtnHtml(cve
      ? ("Explain the " + name + " " + cve + " finding in " + repo + " and how to fix it")
      : ("Explain the risk of " + name + " in " + repo + " and how to fix it"));
    return html + '</div>';
  }

  function detailGeneric(n) {
    var name = n.name || n.id;
    var repo = _popRepo();
    var html = detailHead(n.kind, name) + '<div class="pop">';
    html += popBadge("neutral", KIND_EYEBROW[n.kind] || n.kind);
    html += '<p class="pop__line">Part of the repository structure. Ask the agent for detail.</p>';
    html += askBtnHtml("Tell me about " + name + " in " + repo);
    return html + '</div>';
  }

  function renderDetailInitial() {
    selectedNodeId = null;
    if (cy) cy.nodes().removeClass("selected");
    setDrawer(false);
    el.detailInner.innerHTML =
      '<div class="detail__empty"><span class="d-mark" aria-hidden="true"></span>' +
      '<h2>Nothing selected</h2>' +
      '<p>Click any node in the diagram to inspect it — an entry point’s exposure and advisory context, a function’s source and docstring, or a dependency’s advisories.</p></div>';
  }
  function clearDetail() { renderDetailInitial(); }

  function showDetail(n) {
    if (!n) { clearDetail(); return; }
    var html;
    if (n.kind === "entrypoint") html = detailEntrypoint(n);
    else if (n.kind === "function") html = detailFunction(n);
    else if (n.kind === "dependency") html = detailDependency(n);
    else html = detailGeneric(n);
    el.detailInner.innerHTML = html;
    markSelected(n.id);
    setDrawer(true);
    wireDetail();
    if (el.detail) el.detail.scrollTop = 0;
  }

  function wireDetail() {
    var root = el.detailInner;
    var close = root.querySelector("#detail-close");
    if (close) close.addEventListener("click", function () { resetView(); });
    // Selecting a node already lights its reaching subgraph (the graph tap and the
    // entry-point list both route through lightTrace / lightReverseTrace), so the
    // drawer no longer carries a "light this trace" button.
    // Expand/collapse clamped snippets and docstrings (only when truly overflowing).
    // Dependency drawer: kick off the live AI analysis (or cancel a stale one).
    loadAiAnalysis(root.querySelector(".ai-sec"));
    // "Open in Danger Overview" link(s) in the attack-surface section.
    Array.prototype.forEach.call(root.querySelectorAll(".danger-open"), function (btn) {
      btn.addEventListener("click", function () { openDangerOverview(btn.getAttribute("data-ep") || null); });
    });
    Array.prototype.forEach.call(root.querySelectorAll(".more[data-clamp]"), function (btn) {
      var target = btn.previousElementSibling;
      if (!target || !target.classList.contains("clamp") || target.scrollHeight - target.clientHeight < 2) { btn.remove(); return; }
      btn.addEventListener("click", function () {
        var clamped = target.classList.toggle("clamp");
        btn.textContent = clamped ? "Show more" : "Show less";
      });
    });
  }

  // The kind-filter UI is removed in the minimal view, but the graph still needs
  // its default visibility set (entry points, functions and dependencies on;
  // module/file/doc off) — applyFilter() reads visibleKinds. So this keeps that
  // initialization and simply renders no chips.
  function renderFilters() {
    showTransitive = false;
    kindsPresent().forEach(function (kind) {
      visibleKinds[kind] = !OFF_BY_DEFAULT[kind];
    });
    if (!el.filters) return; // no filter rail in the minimal view
  }

  /* ---------------------------------------------------------------- exposure overlay
     Advisory "exposure" layer. Where the data comes from: a single GET
     /api/enrichment?repo=<name> (same-origin), fired per live-repo view (ACME
     "demo" and "pluginreports") and cached per repo in ENRICH across view
     switches. On 503 ("scan not ready") a couple of retries back off; on 404 /
     a view with no live repo / offline / any network error the overlay simply
     never appears — no error UI, no console spam. Stale fetches are dropped by a
     viewToken + currentViewKey check, so switching bundles can't paint the wrong
     overlay. Everything here is additive context on entry points. */

  var EXP_VALUE = {
    "internet-facing": { cls: "expo--public",   label: "PUBLIC" },
    "internal":        { cls: "expo--internal", label: "INTERNAL" },
    "unknown":         { cls: "expo--unknown",  label: "unverified" }
  };
  var EXP_ORIGIN = { doc: "doc-cited", inferred: "AI-inferred" };

  // Entry-point node's exposure tag for the graph ("public" | "internal" | "").
  function exposureTagFor(id) {
    var ex = exposureOn ? exposure[id] : null;
    if (!ex) return "";
    return ex.value === "internet-facing" ? "public" : (ex.value === "internal" ? "internal" : "");
  }

  // The exposure value badge. `compact` (entry-point list) drops the quiet
  // "unverified" so the list stays uncluttered; the drawer shows it.
  function exposureValueChip(ex, compact) {
    var v = EXP_VALUE[ex.value];
    if (!v) return "";
    if (compact && ex.value !== "internet-facing" && ex.value !== "internal") return "";
    return '<span class="expo ' + v.cls + '">' + esc(v.label) + '</span>';
  }

  // The chip row shared by the list and the drawer header: value badge, an AUTH
  // lock chip when auth is required, and a quiet origin + confidence tag. Every
  // piece is built only from esc()'d server text.
  function exposureChips(ex, compact) {
    if (!ex) return "";
    var html = exposureValueChip(ex, compact);
    if (ex.authentication === "required") {
      html += '<span class="expo expo--auth" title="Authentication required">AUTH</span>';
    }
    var origin = exposureOriginLabel(ex);
    var parts = [];
    if (origin) parts.push(esc(origin));
    if (ex.confidence) parts.push(esc(ex.confidence) + " confidence");
    if (parts.length) {
      html += '<span class="expo-tag" title="Advisory: exposure provenance and confidence">' +
        parts.join(" · ") + '</span>';
    }
    return html;
  }

  // The drawer exposure section: the chip row, the rationale and the source
  // citations (doc path + snippet), all escaped, in a cool dashed card flagged
  // ADVISORY so it never reads as a deterministic verdict.
  function exposureSectionHtml(ex) {
    var origin = exposureOriginLabel(ex) || "assessment";
    var html = '<section class="dsec exposure-sec"><h2 class="dsec__h">Exposure ' +
      '<span class="advisory-flag advisory-flag--expo">Advisory · ' + esc(origin) + '</span></h2>' +
      '<div class="exposure-card">' +
      '<div class="expo-chips expo-chips--drawer">' + exposureChips(ex, false) + '</div>';
    if (ex.rationale) {
      html += '<p class="prose prose--quote clamp">' + esc(ex.rationale) + '</p>' + moreBtn();
    }
    var srcs = Array.isArray(ex.sources) ? ex.sources : [];
    if (srcs.length) {
      html += '<div class="ctxgroup"><div class="ctxgroup__h">Sources ' +
        '<span class="dsec__count">' + srcs.length + '</span></div>';
      srcs.forEach(function (s) {
        html += '<div class="docref"><span class="docref__src">' + esc((s && s.doc) || "doc") + '</span>' +
          '<div class="snip__text clamp">' + esc(String((s && s.snippet) || "").trim()) + '</div>' + moreBtn() + '</div>';
      });
      html += '</div>';
    }
    html += '<p class="advisory-foot">An advisory exposure assessment — where this route is reachable from and whether it needs auth. It adds context; it does not change the deterministic vulnerability verdicts.</p>' +
      '</div></section>';
    return html;
  }

  // Refresh the entry-point rings on the live graph when the overlay changes
  // (toggle, or the fetch resolving after the first render).
  function tintExposureNodes() {
    if (!cy) return;
    cy.batch(function () {
      cy.nodes().forEach(function (node) {
        if (node.data("kind") !== "entrypoint") return;
        node.data("expo", exposureTagFor(node.id()));
      });
    });
  }

  // The per-repo cache entry (created on demand). `note`/`provenance` carry a
  // degraded server note and the enrichment provenance; `warming`/`attackWarming`
  // are true while a 503 poll is still in flight (so "warming" never looks like a
  // clean result). `polling`/`attackPolling` guard against duplicate poll loops.
  function enrichEntry(repo) {
    if (!repo) return null;
    return ENRICH[repo] ||
      (ENRICH[repo] = { fetched: false, exposure: null, inferred: [], likely: [],
                        note: null, provenance: null, warming: false, polling: false,
                        attackFetched: false, attack: null,
                        attackNote: null, attackWarming: false, attackPolling: false });
  }

  // 503 ("scan not ready") backoff schedule. Per-repo overlays warm on the backend
  // over MINUTES (sequential model calls), so a page opened during warm-up must keep
  // polling on a widening interval — not cache empty after ~1.5s and show nothing
  // until a manual reload. Widens to 30s and caps near ~3 min total, then degrades.
  var WARM_RETRY_MS = [1500, 3000, 6000, 12000, 20000, 30000, 30000, 30000, 30000];

  // The degraded/warming copy for an overlay drawer section that has no data yet:
  // surface the server note, else a "still warming…" line — so a scan opened during
  // warm-up or a degraded endpoint never looks identical to "nothing found".
  function overlayWarmHtml(warming, note, label) {
    if (note) return '<section class="dsec"><p class="dim-note">' + esc(String(note)) + '</p></section>';
    if (warming) return '<section class="dsec"><p class="dim-note">' + esc(label + " analysis still warming…") + '</p></section>';
    return "";
  }

  // The exposure origin tag: "doc-cited" vs "AI-inferred" by the finding's origin.
  // But if NO model ran (provenance "offline-heuristic"), an inferred finding came
  // from a heuristic, not the AI — so prefer a neutral "heuristic" label rather than
  // implying a model produced it. Absent provenance keeps the plain origin label.
  function exposureOriginLabel(ex) {
    var base = EXP_ORIGIN[ex && ex.origin];
    if (!base) return null;
    var en = currentRepo && ENRICH[currentRepo];
    if (en && en.provenance === "offline-heuristic" && ex && ex.origin === "inferred") return "heuristic";
    return base;
  }
  function buildLikelyIndex() {
    likelyByDep = {};
    (likelyReachable || []).forEach(function (l) {
      if (l && l.dependency_id) likelyByDep[l.dependency_id] = l;
    });
  }

  // Point the current-view enrichment (exposure + inferred + likely) at the cached
  // entry for this view's repo, or clear it when the view has no live repo. Resets
  // the Proven/Likely toggle to its default (Proven) on every view switch. Called
  // BEFORE a (re)render so a synchronous pass already carries the overlays when the
  // cache is warm.
  function applyViewEnrichment(key) {
    currentViewKey = key;
    currentRepo = (key && BUNDLES[key] && BUNDLES[key].repo) || null;
    reachMode = "proven";
    var entry = currentRepo && ENRICH[currentRepo];
    exposure = (entry && entry.exposure) ? entry.exposure : {};
    inferredEdges = (entry && entry.inferred) ? entry.inferred : [];
    likelyReachable = (entry && entry.likely) ? entry.likely : [];
    buildLikelyIndex();
    // Point the current-view attack surface at this repo's cache (or clear it),
    // and close any open Danger Overview so a view switch never shows stale leads.
    var atk = (entry && entry.attack) ? entry.attack : null;
    attackSurface = (atk && atk.entrypoints) ? atk.entrypoints : {};
    attackSummary = (atk && atk.summary) ? atk.summary : null;
    if (dangerOpen) closeDangerOverview();
  }

  // Fire the one enrichment fetch for a live-repo view (no-op once fetched). The
  // repo rides the query string so one backend can serve several warm scans;
  // ACME ("acme-api") also works with no param, so this stays backward-compatible.
  function ensureEnrichment(key, token) {
    var repo = (BUNDLES[key] && BUNDLES[key].repo) || null;
    if (!repo) { updateExposureLegend(); updateReachModeUI(); return; }
    var entry = enrichEntry(repo);
    if (entry.fetched) { afterEnrichment(key, repo, token); return; }
    if (typeof fetch !== "function") {
      entry.fetched = true; updateExposureLegend(); updateReachModeUI(); return;
    }
    if (entry.polling) { afterEnrichment(key, repo, token); return; } // a poll is already running
    entry.polling = true;
    var tries = 0;
    function attempt() {
      fetch("/api/enrichment?repo=" + encodeURIComponent(repo),
            { headers: { "Accept": "application/json" } }).then(function (r) {
        if (r.status === 503) {                         // scan not ready — keep polling, widening
          if (tries < WARM_RETRY_MS.length) {
            entry.warming = true;
            var delay = WARM_RETRY_MS[tries++];
            reapplyEnrichment(repo);                    // reflect "warming" in the live view
            setTimeout(attempt, delay);
            return null;
          }
          throw new Error("not ready");                 // hard cap — give up, degrade
        }
        if (!r.ok) throw new Error("http " + r.status); // 404 / 5xx — degrade silently
        return r.json();
      }).then(function (d) {
        if (d === null) return;                         // a 503 retry is already scheduled
        entry.fetched = true; entry.polling = false; entry.warming = false;
        entry.exposure = (d && d.exposure && typeof d.exposure === "object") ? d.exposure : null;
        entry.inferred = Array.isArray(d && d.inferred_edges) ? d.inferred_edges : [];
        entry.likely = Array.isArray(d && d.likely_reachable) ? d.likely_reachable : [];
        entry.note = (d && typeof d.note === "string" && d.note) ? d.note : null;
        entry.provenance = (d && typeof d.provenance === "string") ? d.provenance : null;
        reapplyEnrichment(repo);                        // re-apply to whatever view is now live
      }).catch(function () {
        entry.fetched = true; entry.polling = false; entry.warming = false;
        entry.exposure = null; entry.inferred = []; entry.likely = []; // degrade: no overlay
        reapplyEnrichment(repo);
      });
    }
    attempt();
  }

  // Re-apply enrichment to the view that is live NOW (not the one that started the
  // fetch), so a response arriving after a slow warm-up still paints — and a switch
  // away is still respected, because afterEnrichment's own viewToken/currentViewKey
  // guard passes only when the live view is this repo's.
  function reapplyEnrichment(repo) {
    if (currentRepo === repo && currentViewKey && BUNDLES[currentViewKey] &&
        BUNDLES[currentViewKey].repo === repo) {
      afterEnrichment(currentViewKey, repo, viewToken);
    } else {
      updateExposureLegend(); updateReachModeUI();
    }
  }

  // Apply the enrichment once it arrives, unless the user switched away mid-flight
  // (guarded by both the view token and the live view key, so a late response can
  // never paint the wrong scan's overlay).
  function afterEnrichment(key, repo, token) {
    if (token !== viewToken || currentViewKey !== key) {
      updateExposureLegend(); updateReachModeUI();
      return;
    }
    var entry = enrichEntry(repo);
    exposure = entry.exposure || {};
    inferredEdges = entry.inferred || [];
    likelyReachable = entry.likely || [];
    buildLikelyIndex();
    // Exposure side (Phase 1): repaint the route list + graph rings.
    renderEntryPoints();
    if (selectedEp) updateEpButtons(selectedEp);
    tintExposureNodes();
    // Inferred side (Phase 2): the graph may have been built before the fetch
    // resolved, so (re)inject the inferred edges, then apply the current mode.
    refreshInferredElements();
    applyReachMode();
    updateExposureLegend();
    var sel = selectedNodeId && model.index[selectedNodeId];
    if (sel) showDetail(sel); // repaint the open drawer with exposure + likely sections
  }

  /* ---------------------------------------------------------------- inferred edges / likely view
     Phase 2 presentation layer. Inferred edges are added to cytoscape ONLY — never
     to the data model — so trace(), computeDepths(), the funnel and every verdict
     are computed on the deterministic graph exactly as before. The Proven/Likely
     toggle just shows/hides these overlay edges and re-skins the likely-reachable
     deps; it changes nothing about reachability or the counts. */

  // (Re)inject the current view's inferred edges into the live graph. Idempotent:
  // existing inferred edges are removed first, so it is safe to call after a fresh
  // render AND again when a late enrichment response arrives. Endpoints already
  // exist as real nodes (the bundle declares them), so no layout is needed.
  function refreshInferredElements() {
    if (!cy) return;
    cy.edges("[inferred]").remove();
    if (!inferredEdges.length) return;
    var toAdd = [];
    inferredEdges.forEach(function (ie, i) {
      if (!ie || !model.index[ie.src] || !model.index[ie.dst]) return;
      toAdd.push({ group: "edges", data: {
        id: "inf\u0000" + ie.src + "\u0000" + ie.dst + "\u0000" + i,
        source: ie.src, target: ie.dst, kind: "calls", inferred: 1
      }});
    });
    if (toAdd.length) cy.add(toAdd);
  }

  function hasInferredData() {
    return inferredEdges.length > 0 || Object.keys(likelyByDep).length > 0;
  }

  // AI-inferred reachability is ALWAYS ON in the minimal view (no Proven/Likely
  // toggle). The dashed violet inferred edges are shown, and likely-reachable deps
  // wear the distinct violet marker — treated as a first-class but clearly ADVISORY
  // state (the hover tooltip and pop-out label it AI-inferred / advisory). This
  // never touches vuln/vreach/tainted flags, so a dep's deterministic verdict
  // colour is preserved underneath, and it never changes the reachability model
  // or the funnel counts. The dep label stays plain — the violet ring + tooltip
  // carry the advisory meaning.
  function applyReachMode() {
    document.body.classList.add("reach-likely");
    document.body.classList.remove("reach-proven");
    if (cy) {
      cy.batch(function () {
        cy.edges("[inferred]").style("display", "element");
        cy.nodes().forEach(function (node) {
          if (node.data("kind") !== "dependency") return;
          node.data("likely", likelyByDep[node.id()] ? 1 : 0);
        });
      });
    }
    updateReachModeUI();
  }

  function setReachMode(mode) {
    if (mode === reachMode) return;
    if (mode === "likely" && !hasInferredData()) return; // inert without enrichment
    reachMode = mode;
    applyReachMode();
    // The drawer's "Likely reachable (inferred)" copy is mode-independent, so no
    // repaint is needed here (which also avoids re-firing the live AI fetch).
  }

  // Reflect mode + availability on the toggle control and its caption.
  function updateReachModeUI() {
    var ctrl = document.getElementById("reachmode");
    if (!ctrl) return;
    var has = hasInferredData();
    ctrl.setAttribute("data-mode", reachMode);
    ctrl.classList.toggle("is-inert", !has);
    document.body.classList.toggle("has-inferred", has);
    var pb = document.getElementById("reach-proven");
    var lb = document.getElementById("reach-likely");
    if (pb) pb.setAttribute("aria-pressed", String(reachMode === "proven"));
    if (lb) {
      lb.setAttribute("aria-pressed", String(reachMode === "likely"));
      lb.disabled = !has;
      lb.title = has ? "Show AI-inferred likely-reachable edges"
                     : "No AI-inferred edges for this scan";
    }
    var cap = document.getElementById("reachmode-cap");
    if (cap) {
      cap.textContent = reachMode === "likely"
        ? "Likely view · dashed violet edges and LIKELY markers are AI-inferred and advisory — verdicts and counts are unchanged."
        : (has ? "Proven view · deterministic static paths only. Switch to Likely for AI-inferred edges."
               : "Proven view · deterministic static paths only.");
    }
  }

  // The exposure overlay is ALWAYS ON in the minimal view — there is no toggle and
  // no legend swatch group to build (the one-line key lives in index.html and the
  // deep meaning is in the hover tooltip + pop-out). Kept as a no-op so the boot
  // call and updateExposureLegend() (which still toggles the body class the graph
  // tinting reads) stay wired without a control.
  function setupExposureLegend() { /* no overlay toggle in the minimal view */ }

  // Show the exposure legend + toggle only when the current view actually has
  // enrichment exposure data, and reflect the on/off state on the toggle + body.
  function updateExposureLegend() {
    var has = !!currentRepo && !!exposure && Object.keys(exposure).length > 0;
    document.body.classList.toggle("has-exposure", has);
    document.body.classList.toggle("exposure-off", has && !exposureOn);
    if (expToggleBtn) {
      expToggleBtn.setAttribute("aria-pressed", String(exposureOn));
      var lbl = expToggleBtn.querySelector(".exp-toggle__lbl");
      if (lbl) lbl.textContent = exposureOn ? "Exposure overlay" : "Exposure overlay · hidden";
    }
  }

  /* ---------------------------------------------------------------- attack surface (Tier-A AI)
     ADVISORY code-level attack-surface layer (live GET /api/attack-surface?repo=<name>).
     For each public entry point the Tier-A AI pen-tester flags candidate CODE-LEVEL
     vulnerabilities in the app's OWN code as UNVERIFIED HYPOTHESES (provenance
     "ai-hypothesis", advisory true). They are DISTINCT from the deterministic
     dependency findings and are NEVER shown as proven/confirmed/exploitable. This
     layer is additive only: it drives a danger marker on entry-point nodes, an
     advisory drawer section, a dedicated Danger Overview panel and a legend row —
     it never touches the funnel, the dependency verdicts/colors, the exposure/
     likely overlays, or the reachability model. The fetch mirrors the enrichment
     overlay (503-retry, 404/offline silent-degrade, stale-fetch guard). */

  // One entry point's findings (always an array; [] when absent).
  function epFindings(epId) {
    var e = attackSurface && attackSurface[epId];
    return (e && Array.isArray(e.findings)) ? e.findings : [];
  }
  // Worst severity across a set of findings ("" when none / all unrated).
  function worstSeverity(findings) {
    var best = "", bestRank = 0;
    (findings || []).forEach(function (f) {
      var s = String((f && f.severity) || "").toLowerCase();
      var r = DANGER_SEV_RANK[s] || 0;
      if (r > bestRank) { bestRank = r; best = s; }
    });
    return best;
  }
  // The danger severity for an entry-point node, or "" (no marker).
  function dangerSevFor(epId) {
    if (!dangerDataPresent()) return "";
    return worstSeverity(epFindings(epId));
  }
  // Does the current view carry ANY attack-surface finding at all?
  function dangerDataPresent() {
    if (!attackSurface) return false;
    return Object.keys(attackSurface).some(function (id) { return epFindings(id).length > 0; });
  }
  // Order: severity (critical→low), then confidence (high→low).
  function cmpFinding(a, b) {
    var sa = DANGER_SEV_RANK[String((a && a.severity) || "").toLowerCase()] || 0;
    var sb = DANGER_SEV_RANK[String((b && b.severity) || "").toLowerCase()] || 0;
    if (sb !== sa) return sb - sa;
    var ca = CONF_RANK[String((a && a.confidence) || "").toLowerCase()] || 0;
    var cb = CONF_RANK[String((b && b.confidence) || "").toLowerCase()] || 0;
    return cb - ca;
  }
  // Location of a finding — the backend puts file/line/function at the top level,
  // but the contract also allows a nested `location` object, so handle both.
  function findingLoc(f) {
    var loc = (f && f.location && typeof f.location === "object") ? f.location : {};
    function pick(k) { return loc[k] != null ? loc[k] : (f ? f[k] : null); }
    return { file: pick("file"), line: pick("line"), fn: pick("function") };
  }
  // A severity chip, graded by danger severity (never a deterministic-verdict tag).
  function dangerSevChip(sev) {
    var s = String(sev || "").toLowerCase();
    var cls = DANGER_SEV_RANK[s] ? s : "unrated";
    return '<span class="dsev dsev--' + cls + '">' + esc(s ? s.toUpperCase() : "UNRATED") + '</span>';
  }
  // One finding card — shared by the drawer section and the Danger Overview. ALL
  // server text is escaped (rationale through the Markdown-safe renderer, which
  // escapes first). `endpoint` adds a route line (used in a non-grouped context).
  function findingCardHtml(f, endpoint) {
    f = f || {};
    var loc = findingLoc(f);
    var locStr = (loc.file ? String(loc.file) : "") + (loc.line != null ? ":" + loc.line : "");
    var html = '<article class="dfind">';
    html += '<header class="dfind__head">' + dangerSevChip(f.severity) +
      '<span class="dfind__class">' + esc(f.vuln_class || "unspecified") + '</span>' +
      (f.confidence ? '<span class="dfind__conf">' + esc(String(f.confidence)) + ' confidence</span>' : "") +
      '</header>';
    if (f.title) html += '<p class="dfind__title">' + esc(String(f.title)) + '</p>';
    if (endpoint) html += '<p class="dfind__ep"><span class="dfind__k">ENTRY POINT</span> ' + esc(String(endpoint)) + '</p>';
    if (locStr || loc.fn) {
      html += '<p class="dfind__loc">' + (locStr ? esc(locStr) : "") +
        (loc.fn ? ' · <span class="dfind__fn">' + esc(String(loc.fn)) + '()</span>' : "") + '</p>';
    }
    if (f.rationale) html += aiParasHtml(String(f.rationale), "dfind__rationale");
    if (f.data_flow) {
      html += '<p class="dfind__flow"><span class="dfind__k">DATA FLOW</span> ' +
        '<code>' + esc(String(f.data_flow)) + '</code></p>';
    }
    if (f.snippet) html += '<pre class="codeblock dfind__snip">' + esc(String(f.snippet)) + '</pre>';
    html += '</article>';
    return html;
  }
  // The drawer "Attack surface" section for one entry point. Empty string (no-op)
  // when the route has no findings. Clearly headed + footed as UNVERIFIED and
  // separate from the dependency verdicts.
  function attackSurfaceSectionHtml(epId) {
    var findings = epFindings(epId);
    if (!findings.length) return "";
    var sorted = findings.slice().sort(cmpFinding);
    var html = '<section class="dsec attack-sec"><h2 class="dsec__h">Attack surface ' +
      '<span class="advisory-flag advisory-flag--danger">AI · UNVERIFIED</span></h2>' +
      '<div class="attack-card">' +
      '<p class="attack-banner">ATTACK SURFACE · AI-IDENTIFIED · UNVERIFIED</p>' +
      '<p class="advisory-foot">AI-identified candidate vulnerabilities in this app’s own code — ' +
      'hypotheses, not proven, confirmed or exploitable. They are separate from the dependency ' +
      'verdicts below and do not change them or the funnel.</p>';
    sorted.forEach(function (f) { html += findingCardHtml(f, null); });
    html += '<button type="button" class="danger-open" data-ep="' + esc(String(epId)) + '">' +
      'Open in Danger Overview →</button>';
    html += '</div></section>';
    return html;
  }

  // Repaint the entry-point danger rings + label glyphs on the live graph (after
  // the fetch resolves, or on a toggle). Mirrors tintExposureNodes().
  function tintDangerNodes() {
    if (!cy) return;
    cy.batch(function () {
      cy.nodes().forEach(function (node) {
        if (node.data("kind") !== "entrypoint") return;
        var sev = dangerSevFor(node.id());
        node.data("danger", sev ? 1 : 0);
        node.data("dangersev", sev || "");
        var m = model.index[node.id()];
        if (m) node.data("label", (sev ? "⚠ " : "") + labelFor(m));
      });
    });
  }

  // The per-repo attack-surface cache entry fetch (no-op once fetched). Mirrors
  // ensureEnrichment: 503 retries a couple of times, 404 / offline / any error
  // degrades silently to no findings.
  function ensureAttackSurface(key, token) {
    var repo = (BUNDLES[key] && BUNDLES[key].repo) || null;
    if (!repo) { updateDangerUI(); return; }
    var entry = enrichEntry(repo);
    if (entry.attackFetched) { afterAttackSurface(key, repo, token); return; }
    if (typeof fetch !== "function") { entry.attackFetched = true; updateDangerUI(); return; }
    if (entry.attackPolling) { afterAttackSurface(key, repo, token); return; } // poll already running
    entry.attackPolling = true;
    var tries = 0;
    function attempt() {
      fetch("/api/attack-surface?repo=" + encodeURIComponent(repo),
            { headers: { "Accept": "application/json" } }).then(function (r) {
        if (r.status === 503) {                         // analysis not ready — keep polling, widening
          if (tries < WARM_RETRY_MS.length) {
            entry.attackWarming = true;
            var delay = WARM_RETRY_MS[tries++];
            reapplyAttackSurface(repo);                 // reflect "warming" in the live view
            setTimeout(attempt, delay);
            return null;
          }
          throw new Error("not ready");                 // hard cap — give up, degrade
        }
        if (!r.ok) throw new Error("http " + r.status); // 404 / 5xx — degrade silently
        return r.json();
      }).then(function (d) {
        if (d === null) return;                         // a 503 retry is already scheduled
        entry.attackFetched = true; entry.attackPolling = false; entry.attackWarming = false;
        entry.attack = (d && d.entrypoints && typeof d.entrypoints === "object")
          ? { entrypoints: d.entrypoints, summary: (d.summary && typeof d.summary === "object") ? d.summary : null }
          : null;
        entry.attackNote = (d && typeof d.note === "string" && d.note) ? d.note : null;
        reapplyAttackSurface(repo);                     // re-apply to whatever view is now live
      }).catch(function () {
        entry.attackFetched = true; entry.attackPolling = false; entry.attackWarming = false;
        entry.attack = null;                            // degrade: no markers, no overview
        reapplyAttackSurface(repo);
      });
    }
    attempt();
  }

  // Re-apply the attack surface to the view that is live NOW, so a response from a
  // slow warm-up still paints; afterAttackSurface's viewToken/currentViewKey guard
  // keeps a switch-away from painting the wrong scan.
  function reapplyAttackSurface(repo) {
    if (currentRepo === repo && currentViewKey && BUNDLES[currentViewKey] &&
        BUNDLES[currentViewKey].repo === repo) {
      afterAttackSurface(currentViewKey, repo, viewToken);
    } else {
      updateDangerUI();
    }
  }

  // Apply the attack surface once it arrives, unless the user switched away
  // mid-flight (guarded by both the view token and the live view key).
  function afterAttackSurface(key, repo, token) {
    if (token !== viewToken || currentViewKey !== key) { updateDangerUI(); return; }
    var entry = enrichEntry(repo);
    var atk = entry.attack;
    attackSurface = (atk && atk.entrypoints) ? atk.entrypoints : {};
    attackSummary = (atk && atk.summary) ? atk.summary : null;
    tintDangerNodes();
    updateDangerUI();
    if (dangerOpen) renderDangerOverview(dangerFocusEp);
    // Repaint the open entry-point drawer so a late response fills its section.
    var sel = selectedNodeId && model.index[selectedNodeId];
    if (sel && sel.kind === "entrypoint") showDetail(sel);
  }

  // Show/hide the Danger Overview toggle + legend row to match data availability.
  function updateDangerUI() {
    var has = dangerDataPresent();
    document.body.classList.toggle("has-danger", has);
    var tgl = document.getElementById("danger-toggle");
    if (tgl) {
      tgl.hidden = !has;
      var c = document.getElementById("danger-toggle-count");
      if (c) {
        var n = (attackSummary && attackSummary.total_findings != null) ? attackSummary.total_findings : 0;
        c.textContent = n ? String(n) : "";
      }
    }
    if (!has && dangerOpen) closeDangerOverview();
  }

  // Render the Danger Overview body: a summary header (total + by-severity), then
  // every candidate finding across the public surface, grouped by entry point and
  // ranked by worst severity (then count), each finding fully detailed. Framed as
  // unverified AI static analysis that does not change the deterministic results.
  function renderDangerOverview(focusEp) {
    var sumEl = document.getElementById("danger-summary");
    var bodyEl = document.getElementById("danger-body");
    if (!sumEl || !bodyEl) return;
    var ids = Object.keys(attackSurface || {}).filter(function (id) { return epFindings(id).length > 0; });
    var s = attackSummary || {};
    var total = (s.total_findings != null) ? s.total_findings
      : ids.reduce(function (acc, id) { return acc + epFindings(id).length; }, 0);
    var bySev = s.by_severity || {};
    var sevChips = ["critical", "high", "medium", "low"].filter(function (k) { return bySev[k]; })
      .map(function (k) {
        return '<span class="dover-sum__sev dsev dsev--' + k + '">' + esc(k.toUpperCase()) +
          ' <b>' + esc(String(bySev[k])) + '</b></span>';
      }).join("");
    sumEl.innerHTML =
      '<div class="dover-sum__counts">' +
        '<span class="dover-sum__total"><b>' + esc(String(total)) + '</b> candidate finding' +
          (total === 1 ? "" : "s") + '</span>' +
        '<span class="dover-sum__eps">' + esc(String(s.entrypoints_with_findings != null ? s.entrypoints_with_findings : ids.length)) +
          ' entry point' + ((s.entrypoints_with_findings != null ? s.entrypoints_with_findings : ids.length) === 1 ? "" : "s") + ' affected</span>' +
        sevChips +
      '</div>';

    if (!ids.length) {
      // Distinguish "still warming" / degraded from a genuinely clean surface.
      var ea = currentRepo && ENRICH[currentRepo];
      if (ea && ea.attackWarming && !ea.attackFetched) {
        bodyEl.innerHTML = '<p class="dim-note">Attack-surface analysis still warming…</p>';
      } else if (ea && ea.attackNote) {
        bodyEl.innerHTML = '<p class="dim-note">' + esc(String(ea.attackNote)) + '</p>';
      } else {
        bodyEl.innerHTML = '<p class="dim-note">No AI-identified code-level risks for this scan.</p>';
      }
      return;
    }
    ids.sort(function (a, b) {
      var wa = DANGER_SEV_RANK[worstSeverity(epFindings(a))] || 0;
      var wb = DANGER_SEV_RANK[worstSeverity(epFindings(b))] || 0;
      if (wb !== wa) return wb - wa;
      return epFindings(b).length - epFindings(a).length;
    });
    var html = "";
    ids.forEach(function (id) {
      var entry = attackSurface[id] || {};
      var findings = epFindings(id).slice().sort(cmpFinding);
      var label = entry.label || id;
      var focusCls = (focusEp && id === focusEp) ? " is-focus" : "";
      html += '<section class="dover-group' + focusCls + '">' +
        '<header class="dover-group__head">' +
          '<h3 class="dover-group__ep">' + esc(String(label)) + '</h3>' +
          (entry.exposure ? '<span class="dover-group__expo">' + esc(String(entry.exposure)) + '</span>' : "") +
          '<span class="dover-group__count">' + findings.length + ' finding' + (findings.length === 1 ? "" : "s") + '</span>' +
        '</header>';
      findings.forEach(function (f) { html += findingCardHtml(f, null); });
      html += '</section>';
    });
    bodyEl.innerHTML = html;
    var fg = bodyEl.querySelector(".dover-group.is-focus");
    if (fg && fg.scrollIntoView) fg.scrollIntoView({ block: "start" });
  }

  // Open / close / toggle the Danger Overview panel. Opening is a no-op when the
  // current view carries no attack-surface data. Closing returns to the graph.
  function openDangerOverview(focusEp) {
    if (!dangerDataPresent()) return;
    dangerFocusEp = focusEp || null;
    dangerOpen = true;
    renderDangerOverview(dangerFocusEp);
    var panel = document.getElementById("danger-overview");
    if (panel) panel.hidden = false;
    document.body.classList.add("danger-open");
    var tgl = document.getElementById("danger-toggle");
    if (tgl) tgl.setAttribute("aria-pressed", "true");
    if (panel && panel.focus) { try { panel.focus(); } catch (e) {} }
  }
  function closeDangerOverview() {
    dangerOpen = false;
    dangerFocusEp = null;
    var panel = document.getElementById("danger-overview");
    if (panel) panel.hidden = true;
    document.body.classList.remove("danger-open");
    var tgl = document.getElementById("danger-toggle");
    if (tgl) tgl.setAttribute("aria-pressed", "false");
  }
  function toggleDangerOverview() {
    if (dangerOpen) closeDangerOverview(); else openDangerOverview(null);
  }

  /* ---------------------------------------------------------------- graph events */
  function bindGraphEvents() {
    cy.on("tap", "node", function (evt) {
      var node = evt.target;
      // The focused-view cluster stand-in is not a real node — ignore taps.
      if (node.data("kind") === "epcluster") return;
      if (node.data("kind") === "entrypoint") {
        if (selectedEp === node.id()) resetView(); else lightTrace(node.id(), false);
        return;
      }
      var mNode = model.index[node.id()];
      // Clicking a dependency lights its FULL reaching subgraph — every node and
      // edge on any path that reaches it, back to the entry points — then opens
      // its datasheet. (Was: a single incident edge, or one route's forward path.)
      if (node.data("kind") === "dependency") {
        lightReverseTrace(node.id(), false);
        return;
      }
      focusNeighborhood(node);
      showDetail(mNode);
    });
    cy.on("tap", function (evt) { if (evt.target === cy) resetView(); });

    cy.on("mouseover", "node", function (evt) { showTip(evt.target); });
    cy.on("mouseout", "node", function () { hideTip(); });
    cy.on("pan zoom drag", function () { hideTip(); });
  }

  // A SHORT, high-level one-liner. No file:line, no snippet, no data flow — the
  // deep detail lives in the pop-out and the chat agent. AI-advisory states are
  // clearly labelled (AI / advisory / unverified) and never read as proven.
  function showTip(node) {
    if (!el.tooltip) return;
    var id = node.id();
    var n = model.index[id];
    if (!n) return;
    var a = n.attrs || {};
    var line = "";
    if (n.kind === "entrypoint") {
      var route = (a.method ? a.method + " " : "") + (a.path || n.name || id);
      var parts = [];
      if (exposureTagFor(id) === "public") parts.push('<span class="t-ai">PUBLIC</span>');
      if (dangerSevFor(id)) parts.push('<span class="t-danger">⚠ code-level risk (AI, unverified)</span>');
      var w = worstReachedVuln(id);
      if (w) parts.push(w.tainted
        ? '<span class="t-exploit">reaches EXPLOITABLE ' + esc(w.dep.name || w.dep.id) + '</span>'
        : 'reaches ' + esc(w.dep.name || w.dep.id) + ' (reachable)');
      line = '<b>' + esc(route) + '</b>' + (parts.length ? ' — ' + parts.join(' · ') : '');
    } else if (n.kind === "dependency") {
      var name = esc(n.name || id);
      var vs = vulnByDep[id];
      var likely = likelyByDep[id];
      if (vs && vs.tainted) {
        var route2 = taintRoute(findings.filter(function (f) { return f.dependency_id === id; })) ||
          vs.entrypoints[0] || "a public route";
        line = '<b>' + name + '</b> — <span class="t-exploit">EXPLOITABLE</span> via ' + esc(route2);
      } else if (vs && vs.reachable) {
        line = '<b>' + name + '</b> — reachable, not proven exploitable';
      } else if (likely) {
        line = '<b>' + name + '</b> — <span class="t-ai">likely reachable (AI-inferred, advisory)</span>';
      } else if (vs) {
        line = '<b>' + name + '</b> — vulnerable, not reached';
      } else {
        line = '<b>' + name + '</b>' + (a.version ? ' · ' + esc(a.version) : '');
      }
    } else {
      line = '<b>' + esc(n.name || id) + '</b>' +
        (KIND_EYEBROW[n.kind] ? ' · ' + esc(KIND_EYEBROW[n.kind]) : '');
    }
    el.tooltip.innerHTML = line; /* all dynamic pieces went through esc() */
    el.tooltip.hidden = false;
    var bb = node.renderedBoundingBox();
    el.tooltip.style.left = (bb.x1 + bb.w / 2) + "px";
    el.tooltip.style.top = bb.y1 + "px";
  }
  function hideTip() { el.tooltip.hidden = true; }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---------------------------------------------------------------- load */
  // Render the model that buildModel() just populated. Shared by both modes;
  // the vuln overlay is driven entirely by vulnByDep / bundleMeta, which are
  // empty in plain-graph mode (so the original viewer is unchanged).
  function renderAll(name) {
    selectedEp = null;
    visibleKinds = {};
    showTransitive = false;
    el.stage.classList.remove("is-traced"); // drop any trace hint from a prior view
    renderCounts();
    renderFunnel();
    renderBanner();
    renderEntryPoints();
    renderFilters();
    renderReachInitial();
    renderDetailInitial();
    renderVulns();
    renderGraph();
    // Phase-2 overlay: inject inferred edges (if any for this view) and apply the
    // current Proven/Likely mode. No-op visuals when there is no enrichment.
    refreshInferredElements();
    applyReachMode();
    document.body.classList.toggle("has-vulns", !!(bundleMeta && findings.length));
    document.body.classList.toggle("has-transitive", model.nodes.some(isTransitiveDep));
    document.body.classList.toggle("is-focused", focusedMode);
    if (name) el.scanname.textContent = name;
  }

  function countByKind(nodes) {
    var c = {};
    (nodes || []).forEach(function (n) { c[n.kind] = (c[n.kind] || 0) + 1; });
    return c;
  }

  // Reduce a large graph to its security-relevant subgraph:
  //   - every dependency that has a finding (the vulnerable deps),
  //   - every node on a reachable chain from an entry point to a vulnerable dep
  //     (so each "route -> handler -> vulnerable dep" path shows in full),
  //   - the edges among those included nodes only.
  // Entry points that reach a vulnerable dep are kept individually (prominent);
  // the rest are counted and collapsed into one cluster node by toCy().
  function computeFocused(fullGraph) {
    var allNodes = fullGraph.nodes || [];
    var allEdges = fullGraph.edges || [];
    var byId = {};
    allNodes.forEach(function (n) { byId[n.id] = n; });

    var keep = {};     // real node ids to render
    var promEp = {};   // entry points that reach a vulnerable dependency

    // vulnerable dependencies are always shown (reachable or not)
    Object.keys(vulnByDep).forEach(function (id) { if (byId[id]) keep[id] = true; });

    // reachable chains that terminate at a vulnerable dependency
    if (bundleReach && Array.isArray(bundleReach.entrypoints)) {
      bundleReach.entrypoints.forEach(function (ep) {
        (ep.reachable_dependencies || []).forEach(function (rd) {
          if (!vulnByDep[rd.id]) return;
          promEp[ep.id] = true;
          (rd.example_path || []).forEach(function (nid) { if (byId[nid]) keep[nid] = true; });
        });
      });
    }
    Object.keys(promEp).forEach(function (id) { if (byId[id]) keep[id] = true; });

    var nodes = allNodes.filter(function (n) { return keep[n.id]; });
    var edges = allEdges.filter(function (e) { return keep[e.src] && keep[e.dst]; });
    var epTotal = countByKind(allNodes).entrypoint || 0;
    var promCount = Object.keys(promEp).length;

    return {
      graph: { nodes: nodes, edges: edges },
      meta: {
        epTotal: epTotal,
        promEp: promCount,
        clustered: Math.max(0, epTotal - promCount),
        vulnDeps: Object.keys(vulnByDep).length,
        reachablePaths: findings.filter(function (f) { return f.reachable; }).length,
        fullNodes: allNodes.length,
        fullEdges: allEdges.length
      }
    };
  }

  // Shared installer: records full-repo totals, then renders either the whole
  // graph (small) or the curated focused subgraph (large). The vuln overlay is
  // unaffected — it is driven by vulnByDep / bundleMeta, set before this runs.
  function installGraph(fullGraph, name) {
    var allNodes = (fullGraph && fullGraph.nodes) || [];
    repoCounts = countByKind(allNodes);
    focusedMode = allNodes.length > LARGE_GRAPH;
    focusedMeta = null;
    if (focusedMode) {
      var f = computeFocused(fullGraph);
      focusedMeta = f.meta;
      buildModel(f.graph);
    } else {
      buildModel(fullGraph || {});
    }
    renderAll(name);
  }

  // A plain {nodes,edges} graph: structure only, overlay cleared.
  function loadGraph(graph, name) {
    findings = [];
    vulnByDep = {};
    bundleMeta = null;
    bundleReach = null;
    assessments = [];
    triage = [];
    triageByDep = {};
    usage = [];
    usageByDep = {};
    installGraph(graph, name);
  }

  // A self-contained audit bundle {graph, findings, summary, ...}: render the
  // graph from bundle.graph and overlay the findings.
  function loadBundle(bundle, name) {
    findings = Array.isArray(bundle.findings) ? bundle.findings : [];
    bundleMeta = {
      summary: bundle.summary || null,
      offline: !!bundle.offline,
      network_ok: bundle.network_ok,
      notices: bundle.notices || []
    };
    bundleReach = bundle.reachability || null;
    assessments = Array.isArray(bundle.assessments) ? bundle.assessments : [];
    triage = Array.isArray(bundle.triage) ? bundle.triage : [];
    usage = Array.isArray(bundle.usage) ? bundle.usage : [];
    computeVulnState();
    installGraph(bundle.graph || {}, name);
  }

  // Auto-detect: a bundle carries a `graph` object; a plain scan is {nodes:[...]}.
  function isBundle(obj) {
    return !!(obj && obj.graph && Array.isArray(obj.graph.nodes));
  }

  function loadAuto(obj, name) {
    if (isBundle(obj)) { loadBundle(obj, name); return; }
    if (obj && Array.isArray(obj.nodes)) { loadGraph(obj, name); return; }
    throw new Error("unrecognized file");
  }

  el.file.addEventListener("change", function (e) {
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        applyViewEnrichment(null); // a loaded file has no live repo — no enrichment
        loadAuto(JSON.parse(reader.result), f.name);
        setActiveView(null); // a loaded file is none of the switcher views
        updateExposureLegend();
        updateReachModeUI();
      } catch (err) {
        el.scanname.textContent = "Could not read " + f.name +
          " — expected a scan graph (nodes array) or an audit bundle.";
      }
    };
    reader.readAsText(f);
    el.file.value = ""; // allow re-loading the same file
  });

  window.addEventListener("resize", function () { if (cy) cy.resize(); });

  /* ---------------------------------------------------------------- zoom controls */
  // The wheel does the real, continuous zooming; these are discrete nudges and a
  // one-tap "fit", animated toward the viewport centre so the focus stays put.
  function zoomBy(factor) {
    if (!cy) return;
    var next = Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor));
    var centre = { x: cy.width() / 2, y: cy.height() / 2 };
    if (REDUCED) cy.zoom({ level: next, renderedPosition: centre });
    else cy.animate({ zoom: { level: next, renderedPosition: centre } }, { duration: 140, easing: "ease-out" });
  }
  if (el.zoomIn) el.zoomIn.addEventListener("click", function () { zoomBy(1.3); });
  if (el.zoomOut) el.zoomOut.addEventListener("click", function () { zoomBy(1 / 1.3); });
  if (el.zoomFit) el.zoomFit.addEventListener("click", function () {
    if (!cy) return;
    if (REDUCED) cy.fit(undefined, 44);
    else cy.animate({ fit: { eles: cy.elements(":visible"), padding: 44 } }, { duration: 140, easing: "ease-out" });
  });

  /* ---------------------------------------------------------------- views */
  function setActiveView(which) {
    el.viewDemo.setAttribute("aria-pressed", which === "demo" ? "true" : "false");
    if (el.viewPlugin) el.viewPlugin.setAttribute("aria-pressed", which === "pluginreports" ? "true" : "false");
  }

  // The inline sample (vulnerable-app) — always available, and the only option
  // when the page is opened via file:// (no fetch).
  function showSample() {
    applyViewEnrichment("sample"); // the inline sample has no live repo — no enrichment
    if (window.SAMPLE_BUNDLE && isBundle(window.SAMPLE_BUNDLE)) {
      loadBundle(window.SAMPLE_BUNDLE, "sample · vulnerable-app · audit");
    } else if (window.SAMPLE_GRAPH) {
      loadGraph(window.SAMPLE_GRAPH, "sample · vulnerable-app");
    } else {
      el.reachBody.innerHTML = '<p class="reach-none">No bundled sample found. Use “Load a scan” to open a graph.json or an audit bundle.</p>';
    }
    setActiveView("sample");
    updateExposureLegend();
    updateReachModeUI();
    updateDangerUI();
  }

  // Served bundles, fetched lazily on first use and cached. Each is rendered
  // through the normal path; focused mode for big graphs is decided by the
  // existing node-count threshold, not by which bundle this is.
  // `repo` (optional) names the live warm scan behind a view, used for the
  // /api/enrichment?repo=<name> overlay fetch. Views without one show no live
  // enrichment (static bundle only).
  var BUNDLES = {
    demo:   { file: "demo-bundle.json",   label: "ACME API · layered Flask service · audit", btn: el.viewDemo,
              repo: "acme-api",
              hint: "Open the dashboard from a local web server to load the ACME API demo bundle." },
    pluginreports: { file: "plugin-reports-bundle.json", label: "Plugin Reports · reflective Jinja2 render · audit", btn: el.viewPlugin,
              repo: "plugin-reports",
              hint: "Open the dashboard from a local web server to load the Plugin Reports bundle." }
  };
  var viewToken = 0; // latest requested view wins if fetches resolve out of order

  // Resolves true if the view was shown, false if its bundle could not load.
  function showBundle(key) {
    var spec = BUNDLES[key];
    var token = ++viewToken;
    setActiveView(key);
    var ready = bundleCache[key]
      ? Promise.resolve(bundleCache[key])
      : (el.scanname.textContent = "loading " + key + "…",
         fetch(spec.file)
           .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
           .then(function (b) { bundleCache[key] = b; return b; }));
    return ready.then(function (b) {
      if (token === viewToken) {
        applyViewEnrichment(key);      // place the cached overlays (if any) before render
        loadBundle(b, spec.label);
        if (spec.repo) { ensureEnrichment(key, token); ensureAttackSurface(key, token); }
        else { updateExposureLegend(); updateReachModeUI(); updateDangerUI(); }
      }
      return true;
    }, function () {
      spec.btn.disabled = true;
      spec.btn.title = spec.hint;
      if (token === viewToken) showSample();
      return false;
    });
  }

  el.viewDemo.addEventListener("click", function () { showBundle("demo"); });
  if (el.viewPlugin) el.viewPlugin.addEventListener("click", function () { showBundle("pluginreports"); });

  // The Proven/Likely toggle, the Exposure toggle, the Danger Overview panel and
  // the big legend are all gone from the minimal view: AI-advisory states are
  // always on and folded into the node visual language + the hover tooltip, and
  // deep detail is delegated to the chat agent. Their functions remain for the
  // data pipeline but have no controls to wire here.

  /* ---------------------------------------------------------------- boot */
  // Default to the served demo bundle (a small, clean showcase app whose deep
  // reachable paths render in full). If the fetch fails (e.g. opened via
  // file://), fall back to the inline sample exactly as before.
  setupExposureLegend();
  showBundle("demo");
})();
