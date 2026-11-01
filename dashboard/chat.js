/* VScan · Ask VScan chat page.
   Vanilla JS. Sends the full conversation to POST /api/chat each turn.
   Every server-returned string is untrusted and is escaped via esc() before it
   reaches the DOM. */
(function () {
  "use strict";

  // The chat page is the PRIMARY-project assistant, so the repo is explicit on
  // the endpoint — the backend resolves findings against this scan, not whichever
  // one happens to be primary server-side.
  var ENDPOINT = "/api/chat?repo=acme-api";
  var TIMEOUT_MS = 120000;
  var STARTERS = [
    "What's actually exploitable in this project?",
    "Trace the attack path for the worst vulnerability.",
    "Which of these CVEs can I safely ignore, and why?",
    "How do I fix the exploitable one?"
  ];
  var MSG_WARMING = "The scanner is still warming up — try again in a moment.";
  var MSG_NETWORK = "Couldn’t reach the server. Check your connection and try again.";
  var MSG_SERVER = "Something went wrong on the server. Try again.";

  var transcript = document.getElementById("transcript");
  var welcome = document.getElementById("welcome");
  var startersEl = document.getElementById("starters");
  var form = document.getElementById("composer");
  var input = document.getElementById("input");
  var sendBtn = document.getElementById("send");

  /* Conversation history: [{role, content}], sent in full on every turn. */
  var history = [];
  var busy = false;

  /* Escape untrusted text for insertion into HTML (text and attribute context). */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /* Escape first, then turn newlines into <br>. */
  function escMultiline(s) {
    return esc(String(s == null ? "" : s).replace(/\r\n?/g, "\n")).replace(/\n/g, "<br>");
  }

  /* Model replies are Markdown. VScanMd (md.js) escapes first, then applies a
     small allowlisted subset; if it failed to load we fall back to plain text. */
  function mdReply(s) {
    return (window.VScanMd && typeof window.VScanMd.mdToHtml === "function")
      ? window.VScanMd.mdToHtml(s)
      : escMultiline(s);
  }

  function el(tag, cls, html) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html; /* callers pass only esc()'d or static markup */
    return n;
  }

  function scrollDown() {
    transcript.scrollTop = transcript.scrollHeight;
  }

  function setBusy(b) {
    busy = b;
    input.disabled = b;
    sendBtn.disabled = b;
    var chips = startersEl.querySelectorAll("button");
    for (var i = 0; i < chips.length; i++) chips[i].disabled = b;
    form.setAttribute("aria-busy", b ? "true" : "false");
    if (!b) input.focus();
  }

  function autosize() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight + 2, 144) + "px";
  }

  /* ---------------------------------------------------------- rendering */

  function addUser(text) {
    var m = el("div", "msg msg--user");
    m.appendChild(el("div", "msg__who", "You"));
    m.appendChild(el("div", "bubble", escMultiline(text)));
    transcript.appendChild(m);
    scrollDown();
    return m;
  }

  function toolsBlock(calls) {
    var wrap = el("div", "tools");
    wrap.setAttribute("role", "group");
    wrap.setAttribute("aria-label", "MCP tool calls");
    wrap.appendChild(el("p", "tools__head", "MCP tools called &middot; " + calls.length));
    var ul = el("ul", "tools__list");
    calls.forEach(function (c) {
      c = c || {};
      var ok = c.ok !== false;
      var li = el("li", "tool" + (ok ? "" : " tool--err"));
      var html = '<span class="tool__name">' + esc(c.name || "tool") + "</span>";
      if (c.summary) html += '<span class="tool__sum">' + esc(c.summary) + "</span>";
      html += '<span class="tool__state">' + (ok ? "ok" : "failed") + "</span>";
      li.innerHTML = html; /* every dynamic piece above went through esc() */
      ul.appendChild(li);
    });
    wrap.appendChild(ul);
    return wrap;
  }

  function addAssistant(data) {
    var m = el("div", "msg msg--assistant");
    var who = '<span class="meta-dot" aria-hidden="true"></span>Muse';
    if (data.model) who += ' <span class="msg__model">&middot; ' + esc(data.model) + "</span>";
    m.appendChild(el("div", "msg__who", who));
    var calls = Array.isArray(data.tool_calls) ? data.tool_calls : [];
    if (calls.length) m.appendChild(toolsBlock(calls));
    m.appendChild(el("div", "bubble bubble--md", mdReply(data.reply)));
    transcript.appendChild(m);
    scrollDown();
  }

  function addTyping() {
    var t = el("div", "msg msg--assistant");
    t.setAttribute("data-typing", "1");
    t.appendChild(el("div", "typing",
      '<span class="typing__dots" aria-hidden="true"><i></i><i></i><i></i></span>' +
      "<span>Muse is analyzing…</span>"));
    transcript.appendChild(t);
    scrollDown();
    return t;
  }

  function addNotice(text, kind) {
    var n = el("div", "notice " + (kind === "warm" ? "notice--warm" : "notice--err"), esc(text));
    n.setAttribute("role", "alert");
    transcript.appendChild(n);
    scrollDown();
    return n;
  }

  function clearNotices() {
    var ns = transcript.querySelectorAll(".notice");
    for (var i = 0; i < ns.length; i++) ns[i].remove();
  }

  /* ------------------------------------------------------------- sending */

  function send(text) {
    text = String(text || "").trim();
    if (!text || busy) return;

    clearNotices();
    welcome.hidden = true;
    var userNode = addUser(text);
    history.push({ role: "user", content: text });
    input.value = "";
    autosize();
    setBusy(true);
    var typing = addTyping();

    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, TIMEOUT_MS) : null;

    /* Roll back the failed turn so history stays strictly alternating and the
       user can resend the same text. */
    function fail(message, kind) {
      history.pop();
      userNode.remove();
      if (!history.length) welcome.hidden = false;
      input.value = text;
      autosize();
      addNotice(message, kind);
    }

    fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ messages: history }),
      signal: ctrl ? ctrl.signal : undefined
    })
      .then(function (res) {
        if (res.status === 503) return { fail: MSG_WARMING, kind: "warm" };
        if (!res.ok) return { fail: MSG_SERVER };
        return res.json().then(function (data) {
          if (!data || typeof data.reply !== "string") return { fail: MSG_SERVER };
          return { data: data };
        });
      })
      .catch(function () { return { fail: MSG_NETWORK }; })
      .then(function (r) {
        if (timer) clearTimeout(timer);
        typing.remove();
        if (r.fail) {
          fail(r.fail, r.kind);
        } else {
          history.push({ role: "assistant", content: r.data.reply });
          addAssistant(r.data);
        }
        setBusy(false);
      });
  }

  /* -------------------------------------------------------------- wiring */

  STARTERS.forEach(function (p) {
    var b = el("button", "starter", esc(p));
    b.type = "button";
    b.addEventListener("click", function () { send(p); });
    startersEl.appendChild(b);
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    send(input.value);
  });

  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      send(input.value);
    }
  });
  input.addEventListener("input", autosize);

  autosize();
  input.focus();
})();
