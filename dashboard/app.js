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
    renderCounts();
    renderEntryPoints();
    renderFilters();
    renderReachInitial();
    renderVulns();
    renderGraph();
    document.body.classList.toggle("has-vulns", !!(bundleMeta && findings.length));
    if (name) el.scanname.textContent = name;
  }

  // A plain {nodes,edges} graph: structure only, overlay cleared.
  function loadGraph(graph, name) {
    findings = [];
    vulnByDep = {};
    bundleMeta = null;
    buildModel(graph);
    renderAll(name);
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
    computeVulnState();
    buildModel(bundle.graph || {});
    renderAll(name);
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
      } catch (err) {
        el.scanname.textContent = "Could not read " + f.name +
          " — expected a scan graph (nodes array) or an audit bundle.";
      }
    };
    reader.readAsText(f);
    el.file.value = ""; // allow re-loading the same file
  });

  window.addEventListener("resize", function () { if (cy) cy.resize(); });

  /* ---------------------------------------------------------------- boot */
  // Prefer the vulnerability bundle so the overlay shows on open; fall back to
  // the plain structural sample, then to an empty prompt.
  if (window.SAMPLE_BUNDLE && isBundle(window.SAMPLE_BUNDLE)) {
    loadBundle(window.SAMPLE_BUNDLE, "sample · vulnerable-app · audit");
  } else if (window.SAMPLE_GRAPH) {
    loadGraph(window.SAMPLE_GRAPH, "sample · vulnerable-app");
  } else {
    el.reachBody.innerHTML = '<p class="reach-none">No bundled sample found. Use “Load a scan” to open a graph.json or an audit bundle.</p>';
  }
})();
