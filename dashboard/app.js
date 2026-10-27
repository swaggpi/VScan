/* ===========================================================================
   vulnreach · reachability viewer
   Shape-agnostic: renders whatever node/edge kinds are present. The one
   orchestrated moment is the reachability trace lighting up from an entry
   point down to each dependency it reaches.
   =========================================================================== */
(function () {
  "use strict";

  var REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Edges a reachability trace follows, in BFS order: route first, then calls.
  var TRACE_EDGES = { route_to_handler: true, calls: true };

  // Kinds hidden by default to keep the code/dependency subgraph legible.
  var OFF_BY_DEFAULT = { file: true, doc: true };

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
  var model = { nodes: [], edges: [], index: {}, outByKind: {} };
  var visibleKinds = {};
  var selectedEp = null;

  // Vulnerability overlay state (populated only in bundle mode; empty for a
  // plain {nodes,edges} graph, which keeps the original viewer unchanged).
  var findings = [];          // ranked finding dicts from the bundle
  var vulnByDep = {};         // dep node id -> { findings, kev, reachable, worst, entrypoints }
  var bundleMeta = null;      // { summary, offline, network_ok, notices } or null
  var bundleReach = null;     // bundle.reachability (per-entrypoint reachable chains) or null

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
    viewDemo: document.getElementById("view-demo"),
    viewRedash: document.getElementById("view-redash"),
    viewSample: document.getElementById("view-sample"),
    viewFile: document.getElementById("view-file")
  };

  /* ---------------------------------------------------------------- model */
  function buildModel(graph) {
    var nodes = graph.nodes || [];
    var edges = graph.edges || [];
    var index = {}, outByKind = {};
    nodes.forEach(function (n) { index[n.id] = n; });
    edges.forEach(function (e) {
      if (!index[e.src] || !index[e.dst]) return; // drop dangling edges
      (outByKind[e.src] || (outByKind[e.src] = [])).push(e);
    });
    model = { nodes: nodes, edges: edges, index: index, outByKind: outByKind };
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

  /* ---------------------------------------------------------------- cytoscape */
  function cyStyle() {
    return [
      { selector: "node", style: {
        "label": "data(label)", "font-family": "JetBrains Mono, monospace",
        "font-size": 10, "color": "#CFE4F2", "text-valign": "bottom",
        "text-margin-y": 5, "text-wrap": "wrap", "text-max-width": 120,
        "width": 16, "height": 16, "border-width": 1.5,
        "background-color": "#4E7493", "border-color": "#4E7493",
        "transition-property": "background-color, border-color, opacity, width, height, line-color",
        "transition-duration": REDUCED ? "0s" : "260ms"
      }},
      { selector: 'node[kind = "dependency"]', style: {
        "background-color": "#6FB8E0", "border-color": "#6FB8E0", "shape": "round-rectangle",
        "width": 18, "height": 18
      }},
      { selector: 'node[kind = "function"]', style: {
        "background-color": "rgba(159,198,224,0.0)", "border-color": "#9FC6E0",
        "border-width": 1.5, "shape": "ellipse"
      }},
      { selector: 'node[kind = "module"]', style: { "background-color": "#345069", "border-color": "#4E7493", "shape": "round-rectangle" }},
      { selector: 'node[kind = "file"]', style: { "background-color": "rgba(78,116,147,0.25)", "border-color": "#4E7493", "shape": "rectangle" }},
      { selector: 'node[kind = "doc"]', style: { "background-color": "rgba(78,116,147,0.25)", "border-color": "#4E7493", "shape": "diamond" }},
      { selector: 'node[kind = "entrypoint"]', style: {
        "background-color": "#0B2239", "border-color": "#F2B134", "border-width": 2.5,
        "shape": "ellipse", "width": 20, "height": 20, "color": "#F2B134", "font-weight": 600
      }},

      /* focused-view only: the compact stand-in for the entry points that reach
         no vulnerable dependency, so the canvas isn't N loose dots */
      { selector: 'node[kind = "epcluster"]', style: {
        "background-color": "rgba(78,116,147,0.18)", "border-color": "#4E7493",
        "border-width": 1.5, "border-style": "dashed", "shape": "round-rectangle",
        "width": 150, "height": 42, "color": "#8FB2CE", "font-size": 9,
        "text-valign": "center", "text-margin-y": 0, "text-wrap": "wrap",
        "text-max-width": 134, "font-weight": 600
      }},

      /* vulnerability overlay — a red ring marks a dependency with findings */
      { selector: 'node[vuln = 1]', style: {
        "border-color": ALERT, "border-width": 3, "color": "#F79885",
        "overlay-color": ALERT, "overlay-opacity": 0.12, "overlay-padding": 5
      }},
      /* vulnerable AND reachable from a public route — the top visual signal */
      { selector: 'node[vreach = 1]', style: {
        "width": 24, "height": 24, "border-width": 3.5, "font-weight": 600,
        "overlay-opacity": 0.2, "overlay-padding": 8
      }},
      /* actively exploited (KEV) — strongest ring */
      { selector: 'node[kev = 1]', style: { "border-width": 4, "overlay-opacity": 0.26 } },

      { selector: "edge", style: {
        "width": 1, "line-color": "#3C5E7E", "target-arrow-color": "#3C5E7E",
        "target-arrow-shape": "triangle", "arrow-scale": 0.7,
        "curve-style": "bezier", "opacity": 0.75,
        "transition-property": "line-color, target-arrow-color, width, opacity",
        "transition-duration": REDUCED ? "0s" : "220ms"
      }},

      /* off the call-flow spine (unreached functions, module/file/doc) — kept
         visible but visually secondary. Declared before .dim so an active trace
         still dims these further; .lit/.focus come later and override it. */
      { selector: "node.offspine", style: { "opacity": 0.5 } },

      /* dimmed (something else is selected) */
      { selector: ".dim", style: { "opacity": 0.12 } },
      { selector: "edge.dim", style: { "opacity": 0.06 } },

      /* live reachability trace — the one hot signal */
      { selector: "node.lit", style: {
        "background-color": "#F2B134", "border-color": "#F2B134",
        "color": "#F6C96B", "border-width": 2.5, "opacity": 1,
        "overlay-color": "#F2B134", "overlay-opacity": 0.22, "overlay-padding": 7
      }},
      { selector: 'node.lit[kind = "function"]', style: { "background-color": "rgba(242,177,52,0.18)" } },
      { selector: 'node.lit[kind = "entrypoint"]', style: { "background-color": "#1A2E1C", "width": 24, "height": 24, "overlay-padding": 9 } },
      { selector: "edge.lit", style: {
        "line-color": "#F2B134", "target-arrow-color": "#F2B134", "width": 3, "opacity": 1,
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
      { selector: "edge.focus", style: { "line-color": "#6FB8E0", "target-arrow-color": "#6FB8E0", "opacity": 0.9, "width": 1.6 } }
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
        kev: vs && vs.kev ? 1 : 0
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
      minZoom: 0.2, maxZoom: 2.5
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

  // Explicit LAYERED top-down placement (a preset layout we compute, not a
  // force/breadthfirst layout), so the diagram reads bottom-to-top as the call
  // chain: an entry point at the BOTTOM flows UP through call layers to the
  // vulnerable dependency at the TOP. Rows, from top (smallest y) down:
  //   • TOP band:  all `dependency` nodes (reachable or disconnected alike).
  //   • MIDDLE:    `function` nodes in horizontal layers by call depth — DEEPER
  //                functions (closer to a dependency) sit HIGHER, shallower ones
  //                (called straight from a handler) sit LOWER. So going up the
  //                screen follows the call chain toward the dependency.
  //   • BOTTOM band: all `entrypoint` nodes (and the focused-view "+N" cluster).
  // Functions not reachable from any entry point, plus module/file/doc nodes if
  // shown, are not part of the call-flow spine: they go on a dim shelf off to
  // the right, visible but visually secondary, never interleaved with the layers.
  // Only currently-visible nodes are distributed, so toggling a kind re-centers
  // the remaining rows cleanly with no stale positions.
  var COL_W = 180;      // x-spacing within a row
  var ROW_H = 135;      // y-spacing between layers
  var OFF_COL_W = 165;  // off-spine shelf column width
  var OFF_ROW_H = 48;   // off-spine shelf row height

  function runLayout() {
    var depth = computeDepths();
    var vis = cy.nodes(":visible");

    // Deepest visible reachable function sets where the dependency band sits.
    var maxFuncDepth = 0;
    vis.forEach(function (n) {
      if (n.data("kind") === "function" && (n.id() in depth)) {
        maxFuncDepth = Math.max(maxFuncDepth, depth[n.id()]);
      }
    });
    var depsLayer = maxFuncDepth + 1; // dependency band always on top
    var topLayer = depsLayer;

    var layers = {};     // layerIndex -> [nodes] on the call-flow spine
    var offspine = [];   // unreached functions + module/file/doc + unknowns
    function push(L, n) { (layers[L] || (layers[L] = [])).push(n); }

    vis.forEach(function (n) {
      var k = n.data("kind");
      if (k === "entrypoint" || k === "epcluster") {
        push(0, n);                       // bottom band
      } else if (k === "dependency") {
        push(depsLayer, n);               // top band (reachable or not)
      } else if (k === "function" && (n.id() in depth)) {
        push(depth[n.id()], n);           // middle: deeper = higher
      } else {
        offspine.push(n);                 // off-spine shelf
      }
    });

    function sortKey(n) { return String(n.data("label") || n.data("name") || n.id()); }
    function layerY(L) { return (topLayer - L) * ROW_H; }

    // Half-width of the widest spine row — where the off-spine shelf begins.
    var maxHalf = 0;
    Object.keys(layers).forEach(function (k) {
      maxHalf = Math.max(maxHalf, (layers[k].length - 1) / 2 * COL_W);
    });

    cy.batch(function () {
      cy.nodes().removeClass("offspine");

      Object.keys(layers).forEach(function (k) {
        var arr = layers[k];
        arr.sort(function (a, b) { return sortKey(a).localeCompare(sortKey(b)); });
        var c = arr.length;
        var y = layerY(Number(k));
        arr.forEach(function (n, i) {
          n.position({ x: (i - (c - 1) / 2) * COL_W, y: y });
        });
      });

      if (offspine.length) {
        offspine.sort(function (a, b) { return sortKey(a).localeCompare(sortKey(b)); });
        offspine.forEach(function (n) { n.addClass("offspine"); });
        // A compact grid to the right of the spine, filling column by column so
        // it stays a tidy band rather than one long run.
        var spineHeight = topLayer * ROW_H;
        var perCol = Math.max(1, Math.floor(spineHeight / OFF_ROW_H) + 1);
        var offX0 = maxHalf + COL_W * 1.6;
        offspine.forEach(function (n, i) {
          var col = Math.floor(i / perCol), row = i % perCol;
          n.position({ x: offX0 + col * OFF_COL_W, y: row * OFF_ROW_H });
        });
      }
    });

    cy.fit(undefined, 44);
  }

  function applyFilter(preserveSelection) {
    cy.batch(function () {
      cy.nodes().forEach(function (node) {
        var show = visibleKinds[node.data("kind")] !== false;
        node.style("display", show ? "element" : "none");
      });
    });
    runLayout();
    if (preserveSelection && selectedEp) lightTrace(selectedEp, true);
  }

  /* ---------------------------------------------------------------- trace lighting */
  function clearHighlight() {
    cy.elements().removeClass("lit dim focus");
    el.stage.classList.remove("is-traced");
  }

  function lightTrace(epId, instant) {
    selectedEp = epId;
    var res = trace(epId);
    clearHighlight();
    el.stage.classList.add("is-traced");

    cy.elements().addClass("dim");

    var litNodes = cy.nodes().filter(function (n) { return res.nodes[n.id()]; });
    var litEdges = cy.edges().filter(function (e) { return res.edges[e.data("tkey")]; });

    if (REDUCED || instant) {
      litNodes.removeClass("dim").addClass("lit");
      litEdges.removeClass("dim").addClass("lit");
    } else {
      // Energize the circuit by BFS depth: entry first, each hop a beat later.
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
            if ((res.depth[e.target().id()] || 0) === Number(d)) e.removeClass("dim").addClass("lit");
          });
        }, Number(d) * step);
      });
    }

    renderReach(epId, res);
    updateEpButtons(epId);
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
  }

  /* ---------------------------------------------------------------- panels */
  function renderCounts() {
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

  function renderEntryPoints() {
    var eps = model.nodes.filter(function (n) { return n.kind === "entrypoint"; })
      .sort(function (a, b) { return labelFor(a).localeCompare(labelFor(b)); });
    el.eplist.innerHTML = "";
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
    eps.forEach(function (n) {
      var a = n.attrs || {};
      var li = document.createElement("li");
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
      li.appendChild(btn);
      el.eplist.appendChild(li);
    });
  }

  function updateEpButtons(epId) {
    Array.prototype.forEach.call(el.eplist.querySelectorAll(".ep"), function (b) {
      b.setAttribute("aria-pressed", b.dataset.id === epId ? "true" : "false");
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

  /* ---------------------------------------------------------------- vulnerabilities */
  var SEV_RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };

  // Build a per-dependency roll-up from the ranked findings so the graph and
  // the panel agree on what is vulnerable, reachable and actively exploited.
  function computeVulnState() {
    vulnByDep = {};
    findings.forEach(function (f) {
      var id = f.dependency_id;
      if (!id) return;
      var vs = vulnByDep[id] || (vulnByDep[id] = {
        findings: [], kev: false, reachable: false, worst: 0, entrypoints: []
      });
      vs.findings.push(f);
      if (f.kev) vs.kev = true;
      if (f.reachable) vs.reachable = true;
      var rank = SEV_RANK[(f.severity || "").toUpperCase()] || 0;
      if (rank > vs.worst) vs.worst = rank;
      (f.reachable_entrypoints || []).forEach(function (ep) {
        if (vs.entrypoints.indexOf(ep) < 0) vs.entrypoints.push(ep);
      });
    });
  }

  // Map an entry-point LABEL ("POST /import") back to its node id, so clicking
  // a reachable finding can light that route's path.
  function epIdForLabel(label) {
    var match = null;
    model.nodes.forEach(function (n) {
      if (n.kind !== "entrypoint") return;
      var a = n.attrs || {};
      var l = (a.method ? a.method + " " : "") + (a.path || "");
      if (l.trim() === String(label).trim()) match = n.id;
    });
    return match;
  }

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
    el.vulnNote.innerHTML = reachN
      ? '<b>' + reachN + '</b> of ' + findings.length + ' findings reach a public route.'
      : 'None of the ' + findings.length + ' findings reach a public route.';

    var html = '<ul class="vulnlist">';
    findings.forEach(function (f, i) {
      var cve = (f.cve_ids && f.cve_ids.length) ? f.cve_ids.join(", ") : (f.vuln_id || "");
      var epLabel = (f.reachable_entrypoints && f.reachable_entrypoints[0]) || "";
      var epId = f.reachable ? epIdForLabel(epLabel) : null;
      var cls = "vuln" + (f.reachable ? " vuln--reachable" : "");
      var attrs = f.reachable && epId
        ? ' tabindex="0" role="button" data-ep="' + esc(epId) + '"'
          + ' aria-label="Light the path from ' + esc(epLabel) + ' to ' + esc(f.dependency_name) + '"'
        : "";

      html += '<li class="' + cls + '" data-idx="' + i + '"' + attrs + '>';
      html += '<div class="vuln__top"><span class="vuln__name">' + esc(f.dependency_name) +
        (f.version ? ' <span class="vuln__ver">' + esc(f.version) + '</span>' : '') +
        '</span></div>';
      html += '<div class="vuln__cve">' + esc(cve) + '</div>';

      html += '<div class="vuln__tags">';
      html += sevTag(f);
      if (f.kev) html += '<span class="tag tag--kev">KEV</span>';
      if (f.epss != null) html += '<span class="tag tag--epss">EPSS ' + Number(f.epss).toFixed(3) + '</span>';
      if (f.reachable) html += '<span class="tag tag--reach">reachable</span>';
      html += '</div>';

      if (f.reachable) {
        var via = (f.reachable_entrypoints && f.reachable_entrypoints.length)
          ? f.reachable_entrypoints.join(", ") : "a public entry point";
        var path = (f.example_path && f.example_path.length) ? f.example_path.join(" → ") : "";
        html += '<div class="vuln__path">Reachable via <b>' + esc(via) + '</b>' +
          (path ? '<br><span class="path-steps">' + esc(path) + '</span>' : '') + '</div>';
      } else {
        html += '<div class="vuln__verdict">' + esc(verdictText(f)) + '</div>';
      }
      html += '</li>';
    });
    html += '</ul>';
    el.vulnBody.innerHTML = html;

    // Clicking (or Enter/Space on) a reachable finding lights its route.
    Array.prototype.forEach.call(el.vulnBody.querySelectorAll(".vuln--reachable[data-ep]"), function (row) {
      var epId = row.getAttribute("data-ep");
      row.addEventListener("click", function () { lightTrace(epId, false); });
      row.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); lightTrace(epId, false); }
      });
    });
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

  function renderFilters() {
    el.filters.innerHTML = "";
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
      // A reachable vulnerable dep is the demo payoff: clicking it lights the
      // path from the public route that reaches it, as an entry point would.
      var vs = vulnByDep[node.id()];
      if (vs && vs.reachable && vs.entrypoints.length) {
        var epId = epIdForLabel(vs.entrypoints[0]);
        if (epId) { lightTrace(epId, false); return; }
      }
      focusNeighborhood(node);
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
    el.stage.classList.remove("is-traced"); // drop any trace hint from a prior view
    renderCounts();
    renderBanner();
    renderEntryPoints();
    renderFilters();
    renderReachInitial();
    renderVulns();
    renderGraph();
    document.body.classList.toggle("has-vulns", !!(bundleMeta && findings.length));
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

  /* ---------------------------------------------------------------- views */
  function setActiveView(which) {
    el.viewDemo.setAttribute("aria-pressed", which === "demo" ? "true" : "false");
    el.viewRedash.setAttribute("aria-pressed", which === "redash" ? "true" : "false");
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
    demo:   { file: "demo-bundle.json",   label: "demo-app · audit",       btn: el.viewDemo,
              hint: "Open the dashboard from a local web server to load the demo bundle." },
    redash: { file: "redash-bundle.json", label: "redash · big repo · audit", btn: el.viewRedash,
              hint: "Open the dashboard from a local web server to load the redash bundle." }
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

  el.viewSample.addEventListener("click", showSample);
  el.viewDemo.addEventListener("click", function () { showBundle("demo"); });
  el.viewRedash.addEventListener("click", function () { showBundle("redash"); });

  /* ---------------------------------------------------------------- boot */
  // Default to the served demo bundle (a small, clean showcase app whose deep
  // reachable paths render in full). If the fetch fails (e.g. opened via
  // file://), fall back to the inline sample exactly as before.
  showBundle("demo");
})();
