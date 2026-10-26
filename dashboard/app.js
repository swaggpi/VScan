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

  var KIND_LABEL = {
    entrypoint: "entry points", dependency: "dependencies", function: "functions",
    module: "modules", file: "files", doc: "docs"
  };
  var KIND_COLOR = {
    entrypoint: "var(--signal)", dependency: "#6FB8E0", function: "#9FC6E0",
    module: "#4E7493", file: "#4E7493", doc: "#4E7493"
  };

  var cy = null;
  var model = { nodes: [], edges: [], index: {}, outByKind: {} };
  var visibleKinds = {};
  var selectedEp = null;

  var el = {
    counts: document.getElementById("counts"),
    eplist: document.getElementById("eplist"),
    epNote: document.getElementById("ep-note"),
    reachBody: document.getElementById("reach-body"),
    filters: document.getElementById("filters"),
    stage: document.querySelector(".stage"),
    graph: document.getElementById("graph"),
    tooltip: document.getElementById("tooltip"),
    scanname: document.getElementById("scanname"),
    file: document.getElementById("file")
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

      { selector: "edge", style: {
        "width": 1, "line-color": "#3C5E7E", "target-arrow-color": "#3C5E7E",
        "target-arrow-shape": "triangle", "arrow-scale": 0.7,
        "curve-style": "bezier", "opacity": 0.75,
        "transition-property": "line-color, target-arrow-color, width, opacity",
        "transition-duration": REDUCED ? "0s" : "220ms"
      }},

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

      /* neighborhood focus (click a node) */
      { selector: ".focus", style: { "opacity": 1 } },
      { selector: "node.focus", style: { "border-color": "#CFE4F2" } },
      { selector: "edge.focus", style: { "line-color": "#6FB8E0", "target-arrow-color": "#6FB8E0", "opacity": 0.9, "width": 1.6 } }
    ];
  }

  function toCy() {
    var eles = [];
    model.nodes.forEach(function (n) {
      eles.push({ data: {
        id: n.id, kind: n.kind,
        label: labelFor(n),
        name: n.name || n.id
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
    return eles;
  }

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

  function visibleRoots() {
    return cy.nodes('[kind = "entrypoint"]').filter(":visible");
  }

  function runLayout() {
    var vis = cy.elements(":visible");
    var roots = visibleRoots();
    vis.layout({
      name: "breadthfirst",
      directed: true,
      roots: roots.length ? roots : undefined,
      spacingFactor: 1.4,
      padding: 40,
      animate: false,
      fit: true
    }).run();
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
    var counts = {};
    model.nodes.forEach(function (n) { counts[n.kind] = (counts[n.kind] || 0) + 1; });
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
  }

  function renderEntryPoints() {
    var eps = model.nodes.filter(function (n) { return n.kind === "entrypoint"; })
      .sort(function (a, b) { return labelFor(a).localeCompare(labelFor(b)); });
    el.eplist.innerHTML = "";
    if (!eps.length) {
      el.epNote.textContent = "No public entry points were detected in this scan.";
      return;
    }
    el.epNote.textContent = "Public routes the outside world can call.";
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
      if (node.data("kind") === "entrypoint") {
        if (selectedEp === node.id()) resetView(); else lightTrace(node.id(), false);
      } else {
        focusNeighborhood(node);
      }
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
    el.tooltip.innerHTML = '<b>' + esc(n.name || n.id) + '</b>' +
      (extra ? '<br>' + esc(extra) : '') +
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
  function loadGraph(graph, name) {
    buildModel(graph);
    selectedEp = null;
    visibleKinds = {};
    renderCounts();
    renderEntryPoints();
    renderFilters();
    renderReachInitial();
    renderGraph();
    if (name) el.scanname.textContent = name;
  }

  el.file.addEventListener("change", function (e) {
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var graph = JSON.parse(reader.result);
        if (!graph || !Array.isArray(graph.nodes)) throw new Error("missing nodes array");
        loadGraph(graph, f.name);
      } catch (err) {
        el.scanname.textContent = "Could not read " + f.name + " — expected a scan JSON with a nodes array.";
      }
    };
    reader.readAsText(f);
    el.file.value = ""; // allow re-loading the same file
  });

  window.addEventListener("resize", function () { if (cy) cy.resize(); });

  /* ---------------------------------------------------------------- boot */
  if (window.SAMPLE_GRAPH) {
    loadGraph(window.SAMPLE_GRAPH, "sample · vulnerable-app");
  } else {
    el.reachBody.innerHTML = '<p class="reach-none">No bundled sample found. Use “Load a scan” to open a graph.json.</p>';
  }
})();
