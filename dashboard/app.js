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

  // Severity accent used on the canvas (cytoscape styles are canvas-rendered, so
  // they take literal colors, not CSS custom properties). Mirrors --alert.
  var ALERT = "#F2654E";

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

  // Focused-view state. When a loaded graph exceeds LARGE_GRAPH we render only
  // the security-relevant subgraph; these hold the full-repo totals and the
  // curation counts the banner reports. Empty/false for small graphs.
  var focusedMode = false;
  var focusedMeta = null;     // { epTotal, promEp, clustered, vulnDeps, reachablePaths, fullNodes, fullEdges }
  var repoCounts = {};        // kind -> count across the FULL repo (header "Repository totals")

  // Bundles fetched for the header switcher, cached by view key so switching
  // re-renders instantly without re-fetching (redash is 6+ MB).
  var bundleCache = {};

  var el = {
    counts: document.getElementById("counts"),
    layout: document.querySelector(".layout"),
    funnel: document.getElementById("funnel"),
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
    viewRedash: document.getElementById("view-redash"),
    viewTransitive: document.getElementById("view-transitive"),
    viewSample: document.getElementById("view-sample")
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
      // Dependencies — the output layer. A solid cyan neuron, a touch larger.
      { selector: 'node[kind = "dependency"]', style: {
        "background-color": "#6FB8E0", "background-opacity": 0.95,
        "border-color": "#C4E3F6", "border-width": 2,
        "width": 42, "height": 42, "color": "#D7ECF9"
      }},
      // Functions — the hidden layers. A hollow, pale ring over the dark ground.
      { selector: 'node[kind = "function"]', style: {
        "background-color": "#0C2237", "background-opacity": 0.55,
        "border-color": "#9FC6E0", "border-width": 2,
        "width": 30, "height": 30
      }},
      // Structural kinds (off by default) stay circles too, just small and muted.
      { selector: 'node[kind = "module"]', style: { "background-color": "#2C4660", "border-color": "#4E7493", "width": 24, "height": 24 }},
      { selector: 'node[kind = "file"]', style: { "background-color": "rgba(78,116,147,0.28)", "border-color": "#4E7493", "width": 22, "height": 22 }},
      { selector: 'node[kind = "doc"]', style: { "background-color": "rgba(78,116,147,0.28)", "border-color": "#4E7493", "width": 24, "height": 24 }},
      // Entry points — the input layer. A solid amber neuron at the start of the flow.
      { selector: 'node[kind = "entrypoint"]', style: {
        "background-color": "#F2B134", "background-opacity": 0.95,
        "border-color": "#F7CE78", "border-width": 2.5,
        "width": 42, "height": 42, "color": "#F7CE78", "font-weight": 600
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

      /* Dependency risk — three states:
         no CVE = the base blue node; has a CVE but not exploitable = blue + a red
         ring; exploitable (attacker input reaches the call) = a fully red node. */
      { selector: 'node[vuln = 1]', style: {
        "border-color": ALERT, "border-width": 3.5, "color": "#F79885"
      }},
      { selector: 'node[tainted = 1]', style: {
        "background-color": ALERT, "background-opacity": 1,
        "border-color": "#F79885", "border-width": 2.5,
        "width": 44, "height": 44, "font-weight": 600
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

      /* off the call-flow spine (unreached functions, module/file/doc) — kept
         visible but visually secondary. Declared before .dim so an active trace
         still dims these further; .lit/.focus come later and override it. */
      { selector: "node.offspine", style: { "opacity": 0.4, "font-size": 11, "text-opacity": 0.75 } },

      /* dimmed (something else is selected) */
      { selector: ".dim", style: { "opacity": 0.12 } },
      { selector: "edge.dim", style: { "opacity": 0.06 } },

      /* live reachability trace — the one hot signal */
      { selector: "node.lit", style: {
        "background-color": "#F2B134", "border-color": "#F2B134",
        "color": "#F6C96B", "border-width": 2.5, "opacity": 1,
        "overlay-color": "#F2B134", "overlay-opacity": 0.22, "overlay-padding": 7
      }},
      { selector: 'node.lit[kind = "function"]', style: { "background-color": "#F2B134", "background-opacity": 0.9 } },
      { selector: 'node.lit[kind = "entrypoint"]', style: { "background-color": "#F2B134", "width": 46, "height": 46, "overlay-padding": 9 } },
      // The lit trace is a bright amber straight line climbing the layers, with a
      // small arrowhead to show the direction of the call chain.
      { selector: "edge.lit", style: {
        "curve-style": "straight",
        "line-color": "#F2B134", "target-arrow-color": "#F2B134",
        "target-arrow-shape": "triangle", "arrow-scale": 0.8,
        "width": 2.4, "opacity": 1,
        "overlay-color": "#F2B134", "overlay-opacity": 0.12, "overlay-padding": 2
      }},
      /* a lit vulnerable dep keeps its red border: amber path -> red endpoint */
      { selector: 'node.lit[vuln = 1]', style: {
        "border-color": ALERT, "border-width": 3.5,
        "overlay-color": ALERT, "overlay-opacity": 0.24, "overlay-padding": 8
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
      eles.push({ data: {
        id: n.id, kind: n.kind,
        label: labelFor(n),
        name: n.name || n.id,
        // Overlay flags (0 unless an audit bundle marked this dependency).
        vuln: vs ? 1 : 0,
        vreach: vs && vs.reachable ? 1 : 0,
        kev: vs && vs.kev ? 1 : 0,
        // Deterministic escalation flags: the vulnerable function was reached
        // (symbol_match=confirmed), and attacker input reaches it (taint=tainted).
        confirmed: vs && vs.symbolConfirmed ? 1 : 0,
        tainted: vs && vs.tainted ? 1 : 0
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
  // A single call-depth column with very many nodes (e.g. redash's ~50 entry
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
    energize(res, instant, "source");
    renderReachReverse(depId, res);
    if (model.index[depId]) showDetail(model.index[depId]);
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
  }

  // Above this many routes the flat list is a wall, so routes collapse into
  // path-prefix groups. Small repos (the demo's 3) stay flat — no empty ritual.
  var EP_GROUP_THRESHOLD = 12;

  // The segment a route is grouped under: its second meaningful path segment
  // (skipping parameter placeholders like <id>, :id, {id}), or the first if
  // that's all there is. So /api/dashboards, /api/dashboards/<id> and
  // /api/dashboards/favorites all group under "dashboards".
  function epGroupKey(ep) {
    var path = (ep.attrs && ep.attrs.path) || ep.name || ep.id || "";
    var segs = String(path).split("/").filter(Boolean);
    var meaningful = segs.filter(function (s) { return !/^[<:{]/.test(s); });
    return meaningful[1] || meaningful[0] || segs[0] || "/";
  }

  // A route button that selects + traces, exactly as before. Reused flat and
  // inside groups; carries data-id so updateEpButtons can track the active one.
  function makeEpButton(n) {
    var a = n.attrs || {};
    var btn = document.createElement("button");
    btn.className = "ep";
    btn.type = "button";
    btn.setAttribute("aria-pressed", "false");
    btn.dataset.id = n.id;
    var method = document.createElement("span");
    method.className = "ep__method";
    method.textContent = a.method || "ANY";
    var path = document.createElement("span");
    path.className = "ep__path";
    path.textContent = a.path || n.name || n.id;
    btn.appendChild(method); btn.appendChild(path);
    btn.addEventListener("click", function () {
      if (selectedEp === n.id) { resetView(); } else { lightTrace(n.id, false); }
    });
    return btn;
  }

  function renderEntryPoints() {
    var eps = model.nodes.filter(function (n) { return n.kind === "entrypoint"; })
      .sort(function (a, b) { return labelFor(a).localeCompare(labelFor(b)); });
    el.eplist.innerHTML = "";
    el.eplist.classList.remove("eplist--grouped");
    if (!eps.length) {
      el.epNote.textContent = "No public entry points were detected in this scan.";
      return;
    }
    if (focusedMode && focusedMeta) {
      el.epNote.textContent = "Routes that reach a vulnerable dependency. " +
        focusedMeta.clustered + " more reach nothing vulnerable (grouped on the canvas).";
    } else {
      el.epNote.textContent = "Public routes the outside world can call.";
    }

    // Flat list for a handful of routes.
    if (eps.length <= EP_GROUP_THRESHOLD) {
      eps.forEach(function (n) {
        var li = document.createElement("li");
        li.appendChild(makeEpButton(n));
        el.eplist.appendChild(li);
      });
      return;
    }

    // Many routes: collapse into path-prefix groups, each a disclosure.
    el.eplist.classList.add("eplist--grouped");
    var groups = {}, order = [];
    eps.forEach(function (n) {
      var key = epGroupKey(n);
      if (!groups[key]) { groups[key] = []; order.push(key); }
      groups[key].push(n);
    });
    order.sort(function (a, b) { return a.localeCompare(b); });
    order.forEach(function (key) {
      var items = groups[key];
      var li = document.createElement("li");
      var det = document.createElement("details");
      det.className = "epgroup";
      var sum = document.createElement("summary");
      sum.className = "epgroup__sum";
      sum.innerHTML = '<span class="disc__chev" aria-hidden="true"></span>' +
        '<span class="epgroup__name">' + esc(key) + '</span>' +
        '<span class="epgroup__count">' + items.length + '</span>';
      det.appendChild(sum);
      var inner = document.createElement("ul");
      inner.className = "eplist eplist--inner";
      items.forEach(function (n) {
        var ili = document.createElement("li");
        ili.appendChild(makeEpButton(n));
        inner.appendChild(ili);
      });
      det.appendChild(inner);
      li.appendChild(det);
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
    el.reachBody.innerHTML =
      '<p class="panel__empty">No entry point selected. Pick one above to trace what it reaches.</p>';
  }

  function renderReachEmptyFocus(node) {
    el.reachBody.innerHTML =
      '<p class="reach-none">Focusing <b>' + esc(node.data("name")) +
      '</b> and its direct neighbors. Select an entry point to trace reachability.</p>';
  }

  function renderReach(epId, res) {
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
        symbolConfirmed: false, tainted: false, escFinding: null, escRank: -1
      });
      vs.findings.push(f);
      if (f.kev) vs.kev = true;
      if (f.reachable) vs.reachable = true;
      // Deterministic signals: did a resolved path reach the vulnerable function
      // (symbol_match), and does attacker input prove to reach the call (taint)?
      if (f.symbol_match === "confirmed") vs.symbolConfirmed = true;
      if (f.taint === "tainted") vs.tainted = true;
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

  // Open or collapse the detail drawer. The grid column animates from 0 to
  // --detail-w, so when the width actually changes we resize + re-fit the graph
  // once the transition settles, keeping the pipeline centred in the new space.
  function setDrawer(open) {
    if (!el.layout) return;
    var was = el.layout.classList.contains("has-detail");
    el.layout.classList.toggle("has-detail", open);
    if (was !== open) resizeGraph();
  }

  function resizeGraph() {
    if (!cy) return;
    if (window.requestAnimationFrame) window.requestAnimationFrame(function () { cy.resize(); });
    setTimeout(function () {
      if (!cy) return;
      cy.resize();
      var eles = (graphFitEles && graphFitEles.length) ? graphFitEles.filter(":visible") : null;
      if (!eles || !eles.length) eles = cy.nodes(":visible");
      if (!eles.length) return;
      if (REDUCED) cy.fit(eles, GRAPH_PAD);
      else cy.animate({ fit: { eles: eles, padding: GRAPH_PAD } }, { duration: 140, easing: "ease-out" });
    }, 190);
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

  function detailEntrypoint(n) {
    var a = n.attrs || {};
    var label = labelFor(n);
    var html = detailHead("entrypoint", label) + '<div class="detail__body">';

    html += '<section class="dsec"><h2 class="dsec__h">Route</h2><dl class="kv">' +
      '<dt>Method</dt><dd class="is-signal">' + esc(a.method || "ANY") + '</dd>' +
      '<dt>Path</dt><dd>' + esc(a.path || n.name || n.id) + '</dd>' +
      (a.framework ? '<dt>Framework</dt><dd>' + esc(a.framework) + '</dd>' : "") +
      (a.handler ? '<dt>Handler</dt><dd>' + esc(a.handler) + '</dd>' : "") +
      '</dl></section>';

    var res = trace(n.id);
    html += '<section class="dsec"><h2 class="dsec__h">Reaches <span class="dsec__count">' + res.deps.length + '</span></h2>';
    if (res.deps.length) {
      html += '<ul class="deplist">';
      res.deps.forEach(function (d) {
        var da = d.attrs || {}, vs = vulnByDep[d.id];
        html += '<li class="dep"><div class="dep__name">' + esc(d.name || d.id) + '</div><div class="dep__meta">' +
          (da.ecosystem ? '<span class="dep__eco">' + esc(da.ecosystem) + '</span>' : "") +
          (da.version ? '<span class="dep__ver">' + esc(da.version) + '</span>' : "") +
          (vs ? '<span class="tag tag--sev">' + vs.findings.length + " finding" + (vs.findings.length === 1 ? "" : "s") + '</span>' : "") +
          '</div></li>';
      });
      html += '</ul>';
    } else {
      html += '<p class="dim-note">This route resolves no call into a declared dependency.</p>';
    }
    html += '</section>';

    // One primary block — the integrated agent summary + Sources line — with all
    // the depth (badges, rationale, context groups, doc excerpts) tucked one
    // click away under "Details & sources". No assessment → route + reaches only,
    // plus a collapsed docs disclosure when the route is cited in docs.
    var docs = a.docs || [];
    var ms = assessmentsForEpLabel(label);
    if (ms.length) {
      html += assessmentSummaryHtml(ms);
      var detail = assessmentDetailsHtml(ms, docs);
      if (detail) html += '<section class="dsec">' + disclosure("Details & sources", detail, false) + '</section>';
    } else if (docs.length) {
      html += '<section class="dsec">' + disclosure("Mentioned in docs", docsHtml(docs), false) + '</section>';
    }

    return html + '</div>';
  }

  function detailFunction(n) {
    var a = n.attrs || {};
    var qn = a.module ? (a.module + "." + (n.name || "")) : (n.name || n.id);
    var loc = (a.relpath || "") + (a.lineno != null ? ":" + a.lineno : "");
    var html = detailHead("function", n.name || n.id) + '<div class="detail__body">';

    // Lead with the key line: signature, then source location, then docstring.
    html += '<section class="dsec"><h2 class="dsec__h">Signature</h2>' +
      (a.signature ? '<pre class="codeblock">' + esc(a.signature) + '</pre>' : '<p class="dim-note">Not recorded.</p>') +
      (loc ? '<p class="src-line">' + esc(qn) + ' · <span class="src-line__loc">' + esc(loc) + '</span>' +
        (a.is_method ? ' · method' : "") + '</p>'
        : (a.is_method ? '<p class="src-line">' + esc(qn) + ' · method</p>' : '<p class="src-line">' + esc(qn) + '</p>')) +
      '</section>';

    html += '<section class="dsec"><h2 class="dsec__h">Docstring</h2>' +
      (a.docstring ? '<p class="prose clamp">' + esc(a.docstring) + '</p>' + moreBtn() : '<p class="dim-note">No docstring.</p>') +
      '</section>';

    // Secondary detail — docs the function is cited in, and its place in a lit
    // trace — collapsed under one disclosure so the default stays short.
    var extra = "";
    var docs = a.docs || [];
    if (docs.length) {
      extra += '<div class="ctxgroup"><div class="ctxgroup__h">Mentioned in docs ' +
        '<span class="dsec__count">' + docs.length + '</span></div>' + docsHtml(docs) + '</div>';
    }
    if (selectedEp) {
      var res = trace(selectedEp);
      if (res.nodes[n.id]) {
        var ep = model.index[selectedEp];
        extra += '<p class="dim-note">On the lit path from <b>' + esc(ep ? labelFor(ep) : selectedEp) +
          '</b>, call depth ' + (res.depth[n.id] != null ? res.depth[n.id] : "?") + '.</p>';
      }
    }
    if (extra) html += '<section class="dsec">' + disclosure("More context", extra, false) + '</section>';

    return html + '</div>';
  }

  // The MINIMAL dependency drawer: exactly four sections — Package details,
  // Status (escalation verdict as compact badges + one condensed line), Quick
  // summary (the dep-level agent reasoning synthesised from triage + usage), and
  // one collapsed <details> per CVE. Selecting the node already lights its
  // reaching subgraph (the tap handler calls lightReverseTrace), so there is no
  // "light this trace" button here.
  function detailDependency(n) {
    var a = n.attrs || {};
    var vs = vulnByDep[n.id];
    var depFindings = findings.filter(function (f) { return f.dependency_id === n.id; });
    var html = detailHead("dependency", n.name || n.id) + '<div class="detail__body">';

    // (a) Package details — one tidy key/value block.
    html += '<section class="dsec"><h2 class="dsec__h">Package details</h2><dl class="kv">' +
      '<dt>Name</dt><dd>' + esc(n.name || n.id) + '</dd>' +
      (a.version ? '<dt>Version</dt><dd class="is-signal">' + esc(a.version) + '</dd>' : "") +
      (a.ecosystem ? '<dt>Ecosystem</dt><dd>' + esc(a.ecosystem) + '</dd>' : "") +
      (a.source_file ? '<dt>Declared in</dt><dd>' + esc(a.source_file) + '</dd>' : "") +
      '<dt>Scope</dt><dd>' + (a.direct === false ? 'transitive' : 'direct') + '</dd>' +
      '</dl></section>';

    // (b) Status — the escalation verdict as compact badges, then ONE short line:
    // the condensed attacker-input path when exploitable, else the reaching route.
    html += '<section class="dsec"><h2 class="dsec__h">Status</h2>';
    if (vs) {
      var ef = vs.escFinding || depFindings[0] || {};
      var reachOk = !!vs.reachable;
      var symOk = ef.symbol_match === "confirmed" || !!vs.symbolConfirmed;
      var taintOk = ef.taint === "tainted" || !!vs.tainted;
      html += '<div class="statusline">' +
        (reachOk
          ? '<span class="tag tag--reach">reachable</span>'
          : '<span class="verdict verdict--maybe">not reached</span>') +
        (symOk ? '<span class="sym sym--confirmed">vulnerable function confirmed</span>' : "") +
        (taintOk ? '<span class="taint taint--tainted">exploitable</span>' : "") +
        '</div>';
      if (taintOk) {
        var tf = depFindings.filter(function (f) { return f.taint === "tainted" && f.taint_evidence; })[0] || ef;
        var ev = tf.taint_evidence;
        html += '<p class="status-flow"><strong>Exploitable (red).</strong> ' +
          'Attacker input reaches the vulnerable call' +
          (ev ? ' via ' + esc(ev.entrypoint || "a public route") +
            ' — <code>' + esc(ev.source || "source") + '</code> → <code>' + esc(ev.sink_symbol || "sink") + '</code>' : '') +
          '.</p>';
      } else if (reachOk) {
        // Reachable + vulnerable, but taint not proven -> blue node, red ring (not red).
        // State this plainly: reaching the code is not the same as proving it exploitable.
        var via = vs.entrypoints.length ? ' via ' + esc(vs.entrypoints.join(", ")) : '';
        html += '<p class="status-flow"><strong>Not marked exploitable.</strong> ' +
          (symOk ? 'The vulnerable code is reachable' : 'This package is reachable') + via + ', ' +
          'but we did <strong>not</strong> prove that attacker-controlled input reaches the flaw — ' +
          'so it stays a red ring, not a solid red node.</p>';
      } else {
        var dv = (depFindings[0] && depFindings[0].verdict) || "";
        html += '<p class="dim-note">' + esc(verdictText({ verdict: dv })) + '</p>';
      }
    } else {
      html += '<span class="verdict verdict--maybe">No findings matched</span>';
    }
    html += '</section>';

    // (c) Quick summary — the dep-level AGENT REASONING: the triage rationale(s)
    // (strongest verdict first) plus the dynamic-usage summary, synthesised into a
    // short note. Flagged Advisory (heuristic until a model is configured).
    var trows = triageByDep[n.id] || [];
    var u = usageByDep[n.id];
    var reasons = [];
    trows.slice().sort(function (x, y) { return triageRank(y.affected) - triageRank(x.affected); })
      .forEach(function (t) { if (t.rationale && reasons.indexOf(t.rationale) < 0) reasons.push(t.rationale); });
    if (u && u.summary && reasons.indexOf(u.summary) < 0) reasons.push(u.summary);
    var summaryText = reasons.slice(0, 2).join(" ");
    html += '<section class="dsec"><h2 class="dsec__h">Summary</h2>' +
      (summaryText
        ? '<p class="prose clamp">' + esc(summaryText) + '</p>' + moreBtn()
        : '<p class="dim-note">No advisory context.</p>') +
      '</section>';

    // (d) CVEs — one collapsed <details> per CVE. The summary row is just the CVE
    // id + a severity badge; expanding reveals title, bounded advisory text, the
    // CVSS score+label and the fixed version(s). No EPSS / vector fine print.
    html += '<section class="dsec"><h2 class="dsec__h">CVEs' +
      (depFindings.length ? ' <span class="dsec__count">' + depFindings.length + '</span>' : '') + '</h2>';
    if (!depFindings.length) {
      html += '<p class="dim-note">No known vulnerabilities matched this version.</p>';
    } else {
      depFindings.slice().sort(function (x, y) {
        return (y.reachable - x.reachable) ||
          ((SEV_RANK[(y.severity || "").toUpperCase()] || 0) - (SEV_RANK[(x.severity || "").toUpperCase()] || 0));
      }).forEach(function (f) {
        var cve = (f.cve_ids && f.cve_ids.length) ? f.cve_ids.join(", ") : (f.vuln_id || "");
        var sevLabel = (f.severity || "UNKNOWN").toUpperCase();
        var sevCls = "tag tag--sev" + (sevLabel === "CRITICAL" ? " tag--sev-critical" : "");
        var cvssTxt = sevLabel + (f.cvss_score != null ? " · CVSS " + Number(f.cvss_score).toFixed(1) : "");
        var body =
          (f.summary ? '<p class="cve__sum">' + esc(f.summary) + '</p>' : "") +
          (f.details ? '<p class="prose prose--quote clamp">' + esc(f.details) + '</p>' + moreBtn() : "") +
          '<dl class="kv kv--cve">' +
            '<dt>CVSS</dt><dd>' + esc(cvssTxt) + '</dd>' +
            (f.fixed_versions && f.fixed_versions.length
              ? '<dt>Fixed in</dt><dd class="is-signal">' + esc(f.fixed_versions.join(", ")) + '</dd>' : '') +
          '</dl>';
        html += '<details class="disc cve-disc"><summary class="disc__sum">' +
          '<span class="disc__chev" aria-hidden="true"></span>' +
          '<span class="cve-disc__id">' + esc(cve) + '</span>' +
          '<span class="' + sevCls + '">' + esc(sevLabel) + '</span>' +
          '</summary><div class="disc__body">' + body + '</div></details>';
      });
    }
    html += '</section>';

    return html + '</div>';
  }

  function detailGeneric(n) {
    var a = n.attrs || {};
    var html = detailHead(n.kind, n.name || n.id) + '<div class="detail__body">';
    html += '<section class="dsec"><h2 class="dsec__h">' + esc(KIND_EYEBROW[n.kind] || n.kind) + '</h2><dl class="kv">' +
      '<dt>Name</dt><dd>' + esc(n.name || n.id) + '</dd>' +
      (a.relpath ? '<dt>Path</dt><dd>' + esc(a.relpath) + '</dd>' : "") +
      (a.language ? '<dt>Language</dt><dd>' + esc(a.language) + '</dd>' : "") +
      (a.role ? '<dt>Role</dt><dd>' + esc(a.role) + '</dd>' : "") +
      (a.size != null ? '<dt>Size</dt><dd>' + esc(a.size) + ' B</dd>' : "") +
      '</dl></section>';
    if (a.docstring) html += '<section class="dsec"><h2 class="dsec__h">Docstring</h2><p class="prose clamp">' + esc(a.docstring) + '</p>' + moreBtn() + '</section>';
    if (a.excerpt) html += '<section class="dsec"><h2 class="dsec__h">Excerpt</h2><div class="snip__text clamp">' + esc(String(a.excerpt).trim()) + '</div>' + moreBtn() + '</section>';
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
    Array.prototype.forEach.call(root.querySelectorAll(".more[data-clamp]"), function (btn) {
      var target = btn.previousElementSibling;
      if (!target || !target.classList.contains("clamp") || target.scrollHeight - target.clientHeight < 2) { btn.remove(); return; }
      btn.addEventListener("click", function () {
        var clamped = target.classList.toggle("clamp");
        btn.textContent = clamped ? "Show more" : "Show less";
      });
    });
  }

  // A sibling chip to the kind filters: show the transitive (lockfile-only) deps
  // that are hidden by default. Only offered when the model actually holds some.
  function makeTransitiveChip() {
    var btn = document.createElement("button");
    btn.className = "chip chip--transitive";
    btn.type = "button";
    btn.setAttribute("aria-pressed", String(showTransitive));
    var dot = document.createElement("i");
    // Hollow dependency-cyan ring: a dependency, but a secondary one.
    dot.style.background = "transparent";
    dot.style.border = "1.5px solid " + (KIND_COLOR.dependency || "#6FB8E0");
    btn.appendChild(dot);
    btn.appendChild(document.createTextNode("transitive deps"));
    btn.addEventListener("click", function () {
      showTransitive = !showTransitive;
      btn.setAttribute("aria-pressed", String(showTransitive));
      applyFilter(true);
    });
    return btn;
  }

  function renderFilters() {
    el.filters.innerHTML = "";
    showTransitive = false;
    var hasTransitive = model.nodes.some(isTransitiveDep);
    kindsPresent().forEach(function (kind) {
      visibleKinds[kind] = !OFF_BY_DEFAULT[kind];
      var btn = document.createElement("button");
      btn.className = "chip";
      btn.type = "button";
      btn.setAttribute("aria-pressed", String(visibleKinds[kind]));
      var dot = document.createElement("i");
      dot.style.background = KIND_COLOR[kind] || "#4E7493";
      if (kind === "entrypoint" || kind === "function") { dot.style.background = "transparent"; dot.style.border = "1.5px solid " + (KIND_COLOR[kind] || "#9FC6E0"); }
      btn.appendChild(dot);
      btn.appendChild(document.createTextNode(KIND_LABEL[kind] || kind));
      btn.addEventListener("click", function () {
        visibleKinds[kind] = !visibleKinds[kind];
        btn.setAttribute("aria-pressed", String(visibleKinds[kind]));
        applyFilter(true);
      });
      el.filters.appendChild(btn);
      // The transitive toggle rides beside the dependency chip it refines.
      if (kind === "dependency" && hasTransitive) el.filters.appendChild(makeTransitiveChip());
    });
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

  function showTip(node) {
    var n = model.index[node.id()];
    if (!n) return;
    var a = n.attrs || {};
    var extra = "";
    if (n.kind === "dependency") extra = (a.ecosystem || "") + (a.version ? " · " + a.version : "");
    else if (n.kind === "entrypoint") extra = (a.method || "") + " " + (a.path || "");
    else if (a.relpath) extra = a.relpath;
    // In bundle mode, a vulnerable dependency names its findings in the tooltip.
    var vuln = "";
    var vs = vulnByDep[node.id()];
    if (vs) {
      var cves = [];
      vs.findings.forEach(function (f) {
        (f.cve_ids && f.cve_ids.length ? f.cve_ids : [f.vuln_id]).forEach(function (c) {
          if (c && cves.indexOf(c) < 0) cves.push(c);
        });
      });
      vuln = (vs.kev ? "KEV · " : "") +
        vs.findings.length + (vs.findings.length === 1 ? " finding" : " findings") +
        (vs.reachable ? " · reachable" : "") +
        (cves.length ? "<br>" + esc(cves.slice(0, 4).join(", ")) : "");
    }
    el.tooltip.innerHTML = '<b>' + esc(n.name || n.id) + '</b>' +
      (extra ? '<br>' + esc(extra) : '') +
      (vuln ? '<br><span class="t-vuln">' + vuln + '</span>' : '') +
      '<br><span class="t-id">' + esc(n.id) + '</span>';
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
        loadAuto(JSON.parse(reader.result), f.name);
        setActiveView(null); // a loaded file is none of the switcher views
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
    el.viewRedash.setAttribute("aria-pressed", which === "redash" ? "true" : "false");
    el.viewTransitive.setAttribute("aria-pressed", which === "transitive" ? "true" : "false");
    el.viewSample.setAttribute("aria-pressed", which === "sample" ? "true" : "false");
  }

  // The inline sample (vulnerable-app) — always available, and the only option
  // when the page is opened via file:// (no fetch).
  function showSample() {
    if (window.SAMPLE_BUNDLE && isBundle(window.SAMPLE_BUNDLE)) {
      loadBundle(window.SAMPLE_BUNDLE, "sample · vulnerable-app · audit");
    } else if (window.SAMPLE_GRAPH) {
      loadGraph(window.SAMPLE_GRAPH, "sample · vulnerable-app");
    } else {
      el.reachBody.innerHTML = '<p class="reach-none">No bundled sample found. Use “Load a scan” to open a graph.json or an audit bundle.</p>';
    }
    setActiveView("sample");
  }

  // Served bundles, fetched lazily on first use and cached. Each is rendered
  // through the normal path; focused mode for big graphs is decided by the
  // existing node-count threshold, not by which bundle this is.
  var BUNDLES = {
    demo:   { file: "demo-bundle.json",   label: "ACME API · layered Flask service · audit", btn: el.viewDemo,
              hint: "Open the dashboard from a local web server to load the ACME API demo bundle." },
    redash: { file: "redash-bundle.json", label: "redash · real-world repo (200 deps) · audit", btn: el.viewRedash,
              hint: "Open the dashboard from a local web server to load the redash bundle." },
    transitive: { file: "transitive-bundle.json", label: "transitive-app · npm direct+transitive", btn: el.viewTransitive,
              hint: "Open the dashboard from a local web server to load the transitive-app bundle." },
    sample: { file: "healthy-bundle.json", label: "Healthy API · modern FastAPI service · audit", btn: el.viewSample,
              hint: "Open the dashboard from a local web server to load the Healthy API bundle." }
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
      if (token === viewToken) loadBundle(b, spec.label);
      return true;
    }, function () {
      spec.btn.disabled = true;
      spec.btn.title = spec.hint;
      if (token === viewToken) showSample();
      return false;
    });
  }

  el.viewSample.addEventListener("click", function () { showBundle("sample"); });
  el.viewDemo.addEventListener("click", function () { showBundle("demo"); });
  el.viewRedash.addEventListener("click", function () { showBundle("redash"); });
  el.viewTransitive.addEventListener("click", function () { showBundle("transitive"); });

  /* ---------------------------------------------------------------- boot */
  // Default to the served demo bundle (a small, clean showcase app whose deep
  // reachable paths render in full). If the fetch fails (e.g. opened via
  // file://), fall back to the inline sample exactly as before.
  showBundle("demo");
})();
