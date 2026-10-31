"""Agentic advisory chat over the warmed demo scan (the brain behind ``/api/chat``).

This module is the free-form counterpart to :mod:`scanner.web.explain`: where
explain phrases one pre-selected finding, chat lets the Meta/Muse model *answer
questions* about the project by calling VScan's read-only MCP tools over the
already-warmed scan. Like explain it is kept deliberately free of any web
framework (no FastAPI import) so the agent loop can be unit-tested with fakes;
:mod:`scanner.web.app` only has to look up the primary warm scan's repo path and
hand it, the request messages, and an :class:`~scanner.agent.LLMClient` here.

What it does and, just as importantly, what it does NOT do:

* It exposes exactly the **eight read-only** vscan tools (navigation + the two
  "discuss problems" tools). It never exposes the repo-mutating/refresh tools
  (``vscan_apply_upgrade``), and it strips every scan-mutating / result-narrowing
  field (``repo_path`` is injected server-side; ``refresh`` and ``offline`` are
  dropped) so a model can only ever *read* the already-warmed online cache --
  never re-scan, force an offline (empty) finding set, or write a file.
* It invents nothing. The tool functions are reused verbatim
  (:mod:`scanner.mcp.server`); this module never reimplements scanning,
  reachability, taint or any verdict. The system prompt instructs the model to
  answer ONLY from tool results and honours the cardinal rule: never assert a
  vulnerability is exploitable unless a tool result shows a proven taint path.
* It never raises. A missing/unavailable model, a model that loops forever, or
  malformed tool arguments all degrade to a graceful 200 reply plus whatever
  partial tool trace was gathered -- this backs a live demo and must not 500.

The MCP server (and thus the optional ``mcp`` dependency) is imported lazily
inside :func:`build_registry`, so this module -- and the pure agent loop -- stay
importable and testable even where ``mcp`` is not installed.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from scanner.web.explain import model_label

# Bound on tool-calling rounds before we force a final, tools-disabled answer.
MAX_TOOL_ROUNDS = 6

# Fields never surfaced to the model AND force-stripped before every tool call.
# ``repo_path`` is injected server-side (the chat is always about "this project"
# = the warmed demo scan); ``refresh`` would re-scan/bust the warm cache; and
# ``offline`` would hit a different (offline) cache key whose correlation returns
# an EMPTY finding set -- letting the model claim "nothing is exploitable" about
# the real warmed online scan (a false-safe, the cardinal sin). All three are
# dropped to keep every exposed tool strictly read-only over the warmed online
# scan. (Legitimate read-only query fields -- name, node_id, limit, depth,
# direction, kind, entrypoint, explain -- are deliberately NOT dropped.)
_DROP_FIELDS = ("repo_path", "refresh", "offline")

# Short, accurate descriptions for the exposed tools (the model sees these, not
# the long server docstrings). Names must match the MCP tool function names.
_TOOL_DESCRIPTIONS: dict[str, str] = {
    "vscan_scan_overview": (
        "Structural map of this project: node/edge counts, languages, dependency "
        "counts, entry points and the busiest modules/files. Start here to "
        "understand the repo."
    ),
    "vscan_find": (
        "Substring-search the knowledge graph for nodes (by name, id or path) and "
        "get their node ids. Use to turn a human name like 'submit' or 'yaml' "
        "into the id the other tools need. Optional 'kind' filter."
    ),
    "vscan_describe": (
        "Full datasheet for one node id: a function's callers/callees, a "
        "dependency's version/reachability/verdict, or an entry point's reach."
    ),
    "vscan_call_graph": (
        "Expand the call graph around a function node, inward ('in' = callers) or "
        "outward ('out' = callees), up to 'depth' hops."
    ),
    "vscan_trace_entrypoint": (
        "Forward reachability for one entry point id: which functions and "
        "dependencies that public route can reach."
    ),
    "vscan_dep_reachers": (
        "Reverse reachability for one dependency id: which entry points can reach "
        "it (i.e. whether a vulnerable dependency is actually exposed)."
    ),
    "vscan_audit": (
        "The headline ranked, reachability-aware vulnerability findings for this "
        "project (OSV/KEV/EPSS joined with reachability). Use for the prioritized "
        "list of what is wrong."
    ),
    "vscan_finding_detail": (
        "Deep dive on ONE vulnerable dependency id: its CVEs, severities, fixed "
        "versions, reaching entry points, triage and any proven taint path."
    ),
}

# The advisory system prompt. Explains VScan's model and pins the hard rules so
# the model answers only from tool results and never overstates exploitability.
SYSTEM_PROMPT = (
    "You are the VScan security advisor for one specific project (a local source "
    "repository that has already been scanned). Answer the engineer's questions "
    "about THIS project's dependency vulnerabilities by calling the provided "
    "tools and reasoning over their results.\n\n"
    "HOW VSCAN THINKS (explain it this way, never contradict it):\n"
    "- VScan is reachability-aware SCA: it does not just list CVEs, it asks "
    "whether the vulnerable code is actually reachable from a public entry "
    "point, and whether attacker-controlled input can reach it.\n"
    "- REACHABLE IS NOT EXPLOITABLE. A dependency can be reachable yet have no "
    "proven path for attacker input to the vulnerable sink. Only a proven "
    "source->sink taint path makes a finding exploitable.\n"
    "- The four verdict tiers, strongest to weakest: (1) exploitable -- a proven "
    "taint path from an entry point to the vulnerable sink; (2) reachable -- the "
    "vulnerable package/code is reachable but no taint path is proven; (3) "
    "reachable-but-unproven / package-reachable -- reached at the package level "
    "only; (4) not reached -- no path from any entry point.\n\n"
    "HARD RULES:\n"
    "- Answer ONLY from tool results. Never invent a finding, dependency, CVE, "
    "file path, entry point, version or verdict that a tool did not return. If "
    "you do not have a fact, call a tool to get it; prefer calling tools over "
    "guessing.\n"
    "- CARDINAL RULE: never claim a vulnerability is exploitable unless a tool "
    "result shows a proven taint path -- i.e. taint == \"tainted\" or an explicit "
    "proven source->sink path. If something is merely reachable, say so plainly "
    "and say it is not proven exploitable.\n"
    "- Be concise and concrete. When you have enough from the tools, give a "
    "short, direct answer; do not keep calling tools once you can answer."
)

# A nudge used once when the model exhausts its tool-round budget: ask it to
# answer now, with tool use disabled for the final turn.
_FINALIZE_NUDGE = (
    "You have used all available tool-call rounds. Give your best final answer "
    "now using only what the tools have already returned. Do not request more "
    "tools."
)

# Graceful replies for the degraded paths (never a 500 to the client).
_UNAVAILABLE_REPLY = (
    "The advisory model is not available right now, so I can't chat about the "
    "scan at the moment. The scan results are still available via the dashboard "
    "and the explain view."
)
_PARTIAL_REPLY = (
    "I ran into trouble completing that answer. Here is what I was able to gather "
    "from the scan; please try asking again."
)

# Max characters kept in a per-tool trace summary / error string.
_SUMMARY_CLIP = 240


# --------------------------------------------------------------------------
# Tool-schema derivation (OpenAI function schema from a Pydantic input model)
# --------------------------------------------------------------------------


def tool_schema(
    name: str,
    description: str,
    model_cls: Any,
    *,
    drop: tuple[str, ...] = _DROP_FIELDS,
) -> dict[str, Any]:
    """Derive an OpenAI function schema from a Pydantic input model.

    The model's JSON schema is used verbatim except that every field in ``drop``
    (``repo_path`` -- injected server-side -- plus the result-changing
    ``refresh`` / ``offline``) is removed from both ``properties`` and
    ``required``. Any ``$defs`` the
    remaining fields reference (e.g. the ``kind`` / ``direction`` enums) are kept
    so the schema stays self-contained.
    """
    schema = model_cls.model_json_schema()
    props = {k: v for k, v in (schema.get("properties") or {}).items() if k not in drop}
    required = [
        r for r in (schema.get("required") or []) if r not in drop and r in props
    ]
    parameters: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        parameters["required"] = required
    if schema.get("$defs"):
        parameters["$defs"] = schema["$defs"]
    # The input models forbid unknown fields; mirror that for the model too.
    parameters["additionalProperties"] = False
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        },
    }


def _tool_defs() -> list[tuple[str, Callable[[Any], str], Any]]:
    """Return ``(name, function, input_model)`` for the 8 read-only vscan tools.

    Imports :mod:`scanner.mcp.server` lazily so this module stays importable
    without the optional ``mcp`` dependency. The list is intentionally limited to
    the read-only navigation + "discuss problems" tools; the repo-mutating
    ``vscan_apply_upgrade`` (and the fix/prove tools) are never included.
    """
    from scanner.mcp import server as s

    return [
        ("vscan_scan_overview", s.vscan_scan_overview, s.ScanOverviewInput),
        ("vscan_find", s.vscan_find, s.FindInput),
        ("vscan_describe", s.vscan_describe, s.DescribeInput),
        ("vscan_call_graph", s.vscan_call_graph, s.CallGraphInput),
        ("vscan_trace_entrypoint", s.vscan_trace_entrypoint, s.TraceEntrypointInput),
        ("vscan_dep_reachers", s.vscan_dep_reachers, s.DepReachersInput),
        ("vscan_audit", s.vscan_audit, s.AuditInput),
        ("vscan_finding_detail", s.vscan_finding_detail, s.FindingDetailInput),
    ]


def build_registry() -> (
    tuple[list[dict[str, Any]], dict[str, tuple[Callable[[Any], str], Any]]] | None
):
    """Build ``(tool_schemas, dispatch)`` for the exposed tools, or ``None``.

    ``tool_schemas`` is the list of OpenAI function schemas handed to the model;
    ``dispatch`` maps each tool name to ``(function, input_model)`` for
    execution. Returns ``None`` if the MCP server cannot be imported (the
    optional ``mcp`` dependency is absent), so the caller degrades gracefully to
    a no-tools reply rather than crashing.
    """
    try:
        defs = _tool_defs()
    except Exception:  # noqa: BLE001 - missing optional dep / import error: degrade
        return None
    schemas: list[dict[str, Any]] = []
    dispatch: dict[str, tuple[Callable[[Any], str], Any]] = {}
    for name, func, model_cls in defs:
        schemas.append(tool_schema(name, _TOOL_DESCRIPTIONS.get(name, name), model_cls))
        dispatch[name] = (func, model_cls)
    return schemas, dispatch


# --------------------------------------------------------------------------
# Tool execution + trace summaries
# --------------------------------------------------------------------------


def _clip(text: str, limit: int = _SUMMARY_CLIP) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _is_tool_error(result: str) -> bool:
    """The MCP tools return ``"Error: ..."`` strings on failure (never raise)."""
    return isinstance(result, str) and result.startswith("Error:")


def execute_tool(
    func: Callable[[Any], str], model_cls: Any, arguments: dict[str, Any], repo_path: str
) -> tuple[bool, str]:
    """Call one MCP tool with ``repo_path`` injected; return ``(ok, result_str)``.

    The dropped fields (``repo_path``, ``refresh``, ``offline``) are stripped
    from the model's arguments before the input model is built, so the injected
    repo path always wins and neither ``refresh`` (re-scan) nor ``offline`` (an
    empty offline finding set) can ever be forced on -- the warm online cache is
    strictly read-only to the model. A
    validation error (malformed/invalid args from the model) is turned into an
    ``"Error: ..."`` string with ``ok=False`` -- fed back to the model so it can
    recover -- rather than raising.
    """
    clean = {k: v for k, v in (arguments or {}).items() if k not in _DROP_FIELDS}
    try:
        params = model_cls(repo_path=repo_path, **clean)
    except Exception as exc:  # noqa: BLE001 - invalid args: report, let model retry
        return False, f"Error: invalid arguments for this tool: {exc}"
    try:
        result = func(params)
    except Exception as exc:  # noqa: BLE001 - tools shouldn't raise, but never 500
        return False, f"Error: unexpected {type(exc).__name__}: {exc}"
    if not isinstance(result, str):
        result = str(result)
    return (not _is_tool_error(result)), result


def summarize_tool_result(name: str, ok: bool, result: str) -> str:
    """Build a SHORT human summary of a tool result for the "tools used" trace.

    On failure the tool's own ``"Error: ..."`` message is surfaced (clipped). On
    success a per-tool one-liner is derived from the parsed JSON; any shape we
    don't special-case falls back to a generic "returned a result".
    """
    if not ok:
        return _clip(result)
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, ValueError):
        return "returned a result"
    if not isinstance(data, dict):
        return "returned a result"
    try:
        return _clip(_summary_for(name, data))
    except Exception:  # noqa: BLE001 - a summary must never break the response
        return "returned a result"


def _summary_for(name: str, data: dict[str, Any]) -> str:
    if name == "vscan_audit":
        counts = data.get("counts") or {}
        total = counts.get("findings", 0)
        reachable = counts.get("reachable", 0)
        return f"returned {total} ranked finding(s); {reachable} reachable"
    if name == "vscan_scan_overview":
        deps = (data.get("dependencies") or {}).get("total", 0)
        return (
            f"{deps} dependencies, {data.get('entrypoints', 0)} entry points, "
            f"{data.get('functions', 0)} functions"
        )
    if name == "vscan_find":
        matches = data.get("matches") or {}
        return f"{matches.get('total', 0)} match(es) for {data.get('query')!r}"
    if name == "vscan_describe":
        return f"described {data.get('kind', 'node')} {data.get('id', '')}".strip()
    if name == "vscan_call_graph":
        return (
            f"{len(data.get('nodes') or [])} node(s), "
            f"{len(data.get('edges') or [])} edge(s) ({data.get('direction')})"
        )
    if name == "vscan_trace_entrypoint":
        deps = data.get("reachable_dependencies") or []
        return (
            f"reaches {data.get('reachable_function_count', 0)} function(s) and "
            f"{len(deps)} dependency(ies)"
        )
    if name == "vscan_dep_reachers":
        eps = data.get("entrypoints") or []
        return (
            f"{len(eps)} entry point(s) reach {data.get('name', 'the dependency')}; "
            f"verdict {data.get('verdict')}"
        )
    if name == "vscan_finding_detail":
        cves = data.get("cves") or []
        tainted = sum(1 for c in cves if isinstance(c, dict) and c.get("taint") == "tainted")
        return (
            f"{len(cves)} CVE(s) for {data.get('dependency', 'the dependency')}; "
            f"verdict {data.get('verdict')}; {tainted} with a proven taint path"
        )
    return "returned a result"


# --------------------------------------------------------------------------
# The agentic loop
# --------------------------------------------------------------------------

_ALLOWED_ROLES = {"user", "assistant"}


def _normalize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only well-formed user/assistant turns with string content."""
    out: list[dict[str, Any]] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        content = msg.get("content")
        if role in _ALLOWED_ROLES and isinstance(content, str) and content.strip():
            out.append({"role": role, "content": content})
    return out


def _client_available(client: Any) -> bool:
    try:
        return bool(client is not None and client.available())
    except Exception:  # noqa: BLE001 - a duck-typed client must not break us
        return False


def _parse_tool_call(call: Any) -> tuple[str | None, str | None, dict[str, Any] | None, str | None]:
    """Normalize one raw OpenAI ``tool_calls`` entry.

    Returns ``(call_id, name, arguments, error)``. ``arguments`` is the decoded
    JSON object (or ``None`` with ``error`` set when the model emitted arguments
    that are not a JSON object).
    """
    if not isinstance(call, dict):
        return None, None, None, "malformed tool call"
    call_id = call.get("id")
    fn = call.get("function")
    if not isinstance(fn, dict):
        return call_id, None, None, "malformed tool call (no function)"
    name = fn.get("name")
    raw_args = fn.get("arguments")
    if isinstance(raw_args, dict):
        return call_id, name, raw_args, None
    if raw_args in (None, ""):
        return call_id, name, {}, None
    if not isinstance(raw_args, str):
        return call_id, name, None, "tool arguments were not a JSON object"
    try:
        parsed = json.loads(raw_args)
    except (json.JSONDecodeError, ValueError) as exc:
        return call_id, name, None, f"could not parse tool arguments: {exc}"
    if not isinstance(parsed, dict):
        return call_id, name, None, "tool arguments were not a JSON object"
    return call_id, name, parsed, None


def _trace_args(arguments: dict[str, Any] | None) -> dict[str, Any]:
    """The model's arguments as recorded in the trace, minus injected repo_path."""
    if not isinstance(arguments, dict):
        return {}
    return {k: v for k, v in arguments.items() if k != "repo_path"}


def _tool_message(call_id: str | None, content: str) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "tool", "content": content}
    if call_id is not None:
        msg["tool_call_id"] = call_id
    return msg


def run_chat(
    messages: list[dict[str, Any]],
    client: Any,
    *,
    repo_path: str,
    registry: tuple[list[dict[str, Any]], dict[str, tuple[Callable[[Any], str], Any]]]
    | None = None,
    max_rounds: int = MAX_TOOL_ROUNDS,
) -> dict[str, Any]:
    """Run the bounded agentic chat loop and return the ``/api/chat`` body.

    Returns ``{"reply": str, "tool_calls": [...], "model": str}`` where each
    trace entry is ``{"name", "arguments", "ok", "summary"}``. Never raises: an
    unavailable model, a transport failure mid-loop, a model that will not stop
    calling tools, or malformed tool arguments all degrade to a graceful reply
    plus whatever partial trace was gathered.

    The loop: send ``system + messages + tools``; if the model returns tool
    calls, execute each (injecting ``repo_path``), append the results as ``tool``
    messages, and loop; when the model returns a final answer with no tool calls,
    stop and return it. After ``max_rounds`` tool rounds it makes one final call
    with tool use disabled and the finalize nudge.
    """
    label = model_label()
    trace: list[dict[str, Any]] = []

    if not _client_available(client):
        return {"reply": _UNAVAILABLE_REPLY, "tool_calls": trace, "model": label}

    schemas: list[dict[str, Any]] = []
    dispatch: dict[str, tuple[Callable[[Any], str], Any]] = {}
    if registry is not None:
        schemas, dispatch = registry

    convo: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    convo.extend(_normalize_messages(messages))

    try:
        for _ in range(max_rounds):
            turn = client.chat(convo, tools=schemas or None)
            if turn is None:
                return {
                    "reply": _degraded_reply(trace),
                    "tool_calls": trace,
                    "model": label,
                }
            tool_calls = turn.get("tool_calls") or []
            if not tool_calls:
                content = (turn.get("content") or "").strip()
                reply = content or _degraded_reply(trace)
                return {"reply": reply, "tool_calls": trace, "model": label}

            # Keep the protocol well-formed: append the assistant turn that
            # carries the tool_calls before the tool results that answer them.
            convo.append(turn.get("raw") or {"role": "assistant", "tool_calls": tool_calls})

            for call in tool_calls:
                call_id, name, arguments, parse_error = _parse_tool_call(call)
                if parse_error is not None or not name or name not in dispatch:
                    summary = (
                        f"Error: {parse_error}"
                        if parse_error is not None
                        else f"Error: unknown tool {name!r}"
                    )
                    trace.append(
                        {
                            "name": name or "unknown",
                            "arguments": _trace_args(arguments),
                            "ok": False,
                            "summary": _clip(summary),
                        }
                    )
                    convo.append(_tool_message(call_id, summary))
                    continue
                func, model_cls = dispatch[name]
                ok, result = execute_tool(func, model_cls, arguments or {}, repo_path)
                trace.append(
                    {
                        "name": name,
                        "arguments": _trace_args(arguments),
                        "ok": ok,
                        "summary": summarize_tool_result(name, ok, result),
                    }
                )
                convo.append(_tool_message(call_id, result))

        # Budget exhausted: one final answer with tool use disabled.
        convo.append({"role": "user", "content": _FINALIZE_NUDGE})
        final = client.chat(convo, tools=None)
        if final is not None:
            content = (final.get("content") or "").strip()
            if content:
                return {"reply": content, "tool_calls": trace, "model": label}
        return {"reply": _degraded_reply(trace), "tool_calls": trace, "model": label}
    except Exception:  # noqa: BLE001 - a live demo endpoint must never 500
        return {"reply": _degraded_reply(trace), "tool_calls": trace, "model": label}


def _degraded_reply(trace: list[dict[str, Any]]) -> str:
    """A graceful reply for a failed/partial loop, naming any tools that ran."""
    ran = [t["name"] for t in trace if t.get("ok")]
    if ran:
        unique = ", ".join(dict.fromkeys(ran))
        return f"{_PARTIAL_REPLY} (consulted: {unique}.)"
    return _PARTIAL_REPLY
