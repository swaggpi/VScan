/* VScan · tiny, safe Markdown -> HTML renderer, shared by the dashboard (app.js)
   and the chat page (chat.js). Exposes window.VScanMd.mdToHtml(text).

   Security model: the input is UNTRUSTED model text.
     1. NUL characters are stripped (they are used internally as placeholder
        delimiters, so input can never forge one).
     2. The whole string is HTML-escaped (& < > " ') BEFORE any markdown
        transform. Every transform then runs on the escaped string and only ever
        adds tags from a fixed allowlist (p, div, strong, em, code, pre, ul, ol,
        li, a). No raw HTML from the input can survive, and there are no images.
     3. Links are emitted only when the target starts with http:// or https://;
        anything else (javascript:, data:, ...) stays inert literal text. The URL
        is already escaped, so it cannot break out of the href attribute.

   Supported: **bold** / __bold__, *italic* / _italic_, `inline code`,
   ``` fenced code ```, # / ## / ### headings (deeper levels render as ###),
   - / * / + bullet lists, 1. / 1) ordered lists, paragraphs (single newlines
   become <br>), [text](http...) links and bare http(s) URLs. */
(function (root) {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var TOKEN = /\u0000(\d+)\u0000/g;
  var TOKEN_ONLY = /^\u0000(\d+)\u0000$/;

  function mdToHtml(input) {
    var stash = []; // placeholder -> finished (safe) HTML
    function hold(html) { stash.push(html); return "\u0000" + (stash.length - 1) + "\u0000"; }
    function release(s) {
      // Stashed entries only reference lower indices, so this terminates.
      var guard = 0;
      while (/\u0000\d+\u0000/.test(s) && guard++ < 8) {
        s = s.replace(TOKEN, function (_, i) { return stash[+i] || ""; });
      }
      return s;
    }

    // 1+2. Normalise, drop NULs, escape FIRST.
    var text = esc(String(input == null ? "" : input).replace(/\u0000/g, "").replace(/\r\n?/g, "\n"));

    // Fenced code blocks (content is already escaped). Closed fences first, then
    // an unterminated fence swallows the rest (a reply cut off mid-block).
    function codeBlock(code) {
      return "\n\n" + hold('<pre class="md-pre"><code>' + code.replace(/\n$/, "") + "</code></pre>") + "\n\n";
    }
    text = text.replace(/```[\w+#.-]*[ \t]*\n([\s\S]*?)```/g, function (_, code) { return codeBlock(code); });
    text = text.replace(/```[\w+#.-]*[ \t]*\n([\s\S]*)$/, function (_, code) { return codeBlock(code); });

    // Inline transforms on one already-escaped line/paragraph.
    function inline(s) {
      // inline code first: its content is never touched by later rules
      s = s.replace(/(`{1,3})([^`\n]+?)\1/g, function (_, __, code) {
        return hold('<code class="md-code">' + code + "</code>");
      });
      // [text](http...) -- only http(s) targets match, so javascript: etc. never link
      // (a leading "!" is swallowed: images are not supported, only a plain link)
      s = s.replace(/!?\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/gi, function (_, label, url) {
        return hold('<a class="md-link" href="' + url + '" target="_blank" rel="noopener noreferrer">' +
          emphasis(label) + "</a>");
      });
      // bare URLs (stop at an escaped <, >, quote), trimming trailing punctuation
      s = s.replace(/https?:\/\/(?:(?!&(?:lt|gt|quot|#39);)[^\s\u0000])+/gi, function (url) {
        var tail = "";
        for (;;) {
          var c = url.charAt(url.length - 1);
          if (c === ";" && /&amp;$/.test(url)) break; // part of an entity, not punctuation
          if (!/[.,:;!?)\]]/.test(c)) break;
          tail = c + tail;
          url = url.slice(0, -1);
        }
        if (!/^https?:\/\/./i.test(url)) return url + tail;
        return hold('<a class="md-link" href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + "</a>") + tail;
      });
      return emphasis(s);
    }
    function emphasis(s) {
      s = s.replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, "<strong>$1</strong>");
      s = s.replace(/(^|[^\w])__(?=\S)([\s\S]*?\S)__(?![\w])/g, "$1<strong>$2</strong>");
      s = s.replace(/(^|[^*\w])\*(?=[^\s*])([^*\n]*?[^\s*])\*(?!\*)/g, "$1<em>$2</em>");
      s = s.replace(/(^|[^\w])_(?=[^\s_])([^_\n]*?[^\s_])_(?![\w])/g, "$1<em>$2</em>");
      return s;
    }

    // 3. Block pass, line by line.
    var lines = text.split("\n");
    var out = [];
    var para = [];
    var list = null; // { tag, start, items[] }

    function flushPara() {
      if (para.length) {
        out.push('<p class="md-p">' + para.map(inline).join("<br>") + "</p>");
        para = [];
      }
    }
    function flushList() {
      if (!list) return;
      out.push("<" + list.tag + (list.start > 1 ? ' start="' + list.start + '"' : "") +
        ' class="md-' + list.tag + '">' +
        list.items.map(function (li) { return "<li>" + inline(li) + "</li>"; }).join("") +
        "</" + list.tag + ">");
      list = null;
    }

    lines.forEach(function (raw) {
      var line = raw.replace(/\s+$/, "");
      var m;
      if (!line.trim()) { flushPara(); flushList(); return; }
      if ((m = TOKEN_ONLY.exec(line.trim()))) { // a fenced code block
        flushPara(); flushList(); out.push(release(stash[+m[1]])); return;
      }
      if ((m = /^\s{0,3}(#{1,6})\s+(.+?)(?:\s+#+)?$/.exec(line))) {
        flushPara(); flushList();
        var lvl = Math.min(m[1].length, 3);
        out.push('<div class="md-h md-h' + lvl + '" role="heading" aria-level="' + (lvl + 2) + '">' +
          inline(m[2]) + "</div>");
        return;
      }
      if ((m = /^\s*[-*+]\s+(.*)$/.exec(line))) {
        flushPara();
        if (!list || list.tag !== "ul") { flushList(); list = { tag: "ul", start: 1, items: [] }; }
        list.items.push(m[1]);
        return;
      }
      if ((m = /^\s*(\d{1,9})[.)]\s+(.*)$/.exec(line))) {
        flushPara();
        if (!list || list.tag !== "ol") { flushList(); list = { tag: "ol", start: parseInt(m[1], 10), items: [] }; }
        list.items.push(m[2]);
        return;
      }
      if (list && /^\s+\S/.test(line)) { // indented continuation of the last item
        list.items[list.items.length - 1] += " " + line.trim();
        return;
      }
      flushList();
      para.push(line.trim());
    });
    flushPara();
    flushList();

    return release(out.join(""));
  }

  var api = { mdToHtml: mdToHtml, esc: esc };
  root.VScanMd = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));
