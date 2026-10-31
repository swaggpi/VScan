"""Tests for the ``/api/chat`` backend -- schema derivation, the agent loop,
trace summaries, and graceful degradation.

These never touch the network, a real scan, or the optional ``mcp`` dependency.
The agent loop is driven with a scripted, duck-typed chat client and a trivial
in-memory fake tool injected as the registry, so the loop logic is exercised in
isolation (mirroring how :mod:`tests.test_web_explain` hand-builds finding dicts
and canned clients). A second group uses ``importorskip("mcp")`` to assert the
*real* exposed registry is the 8 read-only tools with ``repo_path`` stripped.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from scanner.web import chat as chat_mod


# -- fakes --------------------------------------------------------------------


class _FakeInput:
    """Stand-in for a Pydantic input model: records the kwargs it was built with."""

    def __init__(self, **kwargs: Any) -> None:
        self.received = kwargs


class _RaisingInput:
    """Input model that rejects its arguments (simulates validation failure)."""

    def __init__(self, **kwargs: Any) -> None:
        raise ValueError("bad field")


class _FakeChatClient:
    """Scripted, duck-typed chat client (``available`` + ``chat``).

    ``turns`` is consumed one entry per :meth:`chat` call; each entry is either a
    turn dict (``{content, tool_calls, raw}``) or ``None`` (a transport failure).
    When ``finalize`` is set it is returned for any call made with ``tools=None``
    (the tools-disabled finalize turn), regardless of the script.
    """

    def __init__(
        self,
        turns: list[Any],
        *,
        available: bool = True,
        finalize: Any = None,
    ) -> None:
        self._turns = list(turns)
        self._available = available
        self._finalize = finalize
        self.calls: list[dict[str, Any]] = []

    def available(self) -> bool:
        return self._available

    def chat(self, messages: list[dict[str, Any]], tools: Any = None) -> Any:
        self.calls.append({"messages": list(messages), "tools": tools})
        if tools is None and self._finalize is not None:
            return self._finalize
        return self._turns.pop(0) if self._turns else None


def _tool_call(name: str, arguments: Any, call_id: str = "c1") -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }


def _turn(content: Any, tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    tcs = tool_calls or []
    return {
        "content": content,
        "tool_calls": tcs,
        "raw": {"role": "assistant", "content": content, "tool_calls": tcs},
    }


# -- schema derivation --------------------------------------------------------


class _SchemaModel:
    """Duck-typed model exposing ``model_json_schema`` like Pydantic v2."""

    @staticmethod
    def model_json_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "query": {"type": "string"},
                "kind": {"$ref": "#/$defs/Kind"},
                "limit": {"type": "integer", "default": 30},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["repo_path", "query"],
            "$defs": {"Kind": {"enum": ["entrypoint", "dependency"]}},
        }


def test_tool_schema_omits_repo_path_and_refresh():
    schema = chat_mod.tool_schema("vscan_find", "find nodes", _SchemaModel)
    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "vscan_find"
    assert fn["description"] == "find nodes"
    props = fn["parameters"]["properties"]
    # repo_path (injected) and refresh (scan-mutating) are gone; the rest remain.
    assert "repo_path" not in props
    assert "refresh" not in props
    assert set(props) == {"query", "kind", "limit"}
    # repo_path dropped from required; a still-present required field is kept.
    assert fn["parameters"]["required"] == ["query"]
    # Referenced enum defs are preserved so the schema stays self-contained.
    assert fn["parameters"]["$defs"] == {"Kind": {"enum": ["entrypoint", "dependency"]}}
    assert fn["parameters"]["additionalProperties"] is False


class _OfflineSchemaModel:
    """A tool model carrying the result-narrowing ``offline`` field (as the real
    ``AuditInput`` / ``FindingDetailInput`` do) plus legit read-only fields."""

    @staticmethod
    def model_json_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "dep_id": {"type": "string"},
                "offline": {"type": "boolean", "default": False},
                "explain": {"type": "boolean", "default": True},
            },
            "required": ["repo_path", "dep_id"],
        }


def test_tool_schema_omits_offline_keeps_legit_fields():
    # ``offline`` forces a different (empty) offline result set and so must be
    # dropped, exactly like ``repo_path`` / ``refresh``; the read-only query
    # fields (dep_id, explain) stay.
    assert "offline" in chat_mod._DROP_FIELDS
    schema = chat_mod.tool_schema("vscan_finding_detail", "detail", _OfflineSchemaModel)
    props = schema["function"]["parameters"]["properties"]
    assert "offline" not in props
    assert "repo_path" not in props
    assert set(props) == {"dep_id", "explain"}
    # repo_path dropped from required; a still-present required field is kept.
    assert schema["function"]["parameters"]["required"] == ["dep_id"]


# -- the agent loop -----------------------------------------------------------


def test_loop_executes_tool_then_returns_final_content():
    captured: dict[str, Any] = {}

    def fake_audit(params: _FakeInput) -> str:
        captured["repo_path"] = params.received.get("repo_path")
        captured["explain"] = params.received.get("explain")
        return json.dumps({"counts": {"findings": 3, "reachable": 1}, "findings": []})

    registry = (
        [{"type": "function", "function": {"name": "vscan_audit"}}],
        {"vscan_audit": (fake_audit, _FakeInput)},
    )
    client = _FakeChatClient(
        [
            _turn(None, [_tool_call("vscan_audit", json.dumps({"explain": True}))]),
            _turn("The project has 3 findings; 1 is reachable."),
        ]
    )

    out = chat_mod.run_chat(
        [{"role": "user", "content": "what's vulnerable?"}],
        client,
        repo_path="/warm/repo",
        registry=registry,
    )

    assert out["reply"] == "The project has 3 findings; 1 is reachable."
    # repo_path was injected server-side; the model never supplied it.
    assert captured["repo_path"] == "/warm/repo"
    assert captured["explain"] is True
    assert len(out["tool_calls"]) == 1
    entry = out["tool_calls"][0]
    assert entry["name"] == "vscan_audit"
    assert entry["ok"] is True
    assert entry["arguments"] == {"explain": True}  # trace shows model args only
    assert "repo_path" not in entry["arguments"]
    assert "3 ranked finding" in entry["summary"]
    assert "reachable" in entry["summary"]
    assert out["model"].startswith("Meta Muse")


def test_loop_feeds_malformed_args_back_and_recovers():
    registry = ([], {"vscan_audit": (lambda p: "{}", _FakeInput)})
    client = _FakeChatClient(
        [
            _turn(None, [_tool_call("vscan_audit", "{not valid json")]),
            _turn("Sorry about that -- here is the answer."),
        ]
    )

    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}],
        client,
        repo_path="/r",
        registry=registry,
    )

    assert out["reply"] == "Sorry about that -- here is the answer."
    assert len(out["tool_calls"]) == 1
    assert out["tool_calls"][0]["ok"] is False
    assert out["tool_calls"][0]["summary"].startswith("Error:")
    # The loop appended a tool-result message so the model could recover: it did.
    assert len(client.calls) == 2


def test_loop_records_unknown_tool_as_error():
    registry = ([], {})
    client = _FakeChatClient(
        [
            _turn(None, [_tool_call("vscan_bogus", "{}")]),
            _turn("done"),
        ]
    )
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}], client, repo_path="/r", registry=registry
    )
    assert out["reply"] == "done"
    assert out["tool_calls"][0]["ok"] is False
    assert "unknown tool" in out["tool_calls"][0]["summary"]


def test_loop_cutoff_forces_tools_disabled_final_answer():
    # A client that keeps asking for tools, then answers once tools are disabled.
    registry = (
        [{"type": "function", "function": {"name": "vscan_audit"}}],
        {"vscan_audit": (lambda p: json.dumps({"counts": {}}), _FakeInput)},
    )
    looping = _turn(None, [_tool_call("vscan_audit", "{}")])
    client = _FakeChatClient(
        [looping, looping],  # both rounds request a tool
        finalize=_turn("Final answer after cutoff."),
    )

    out = chat_mod.run_chat(
        [{"role": "user", "content": "loop forever"}],
        client,
        repo_path="/r",
        registry=registry,
        max_rounds=2,
    )

    assert out["reply"] == "Final answer after cutoff."
    # Two tool rounds happened, then a third call with tools disabled.
    assert len(out["tool_calls"]) == 2
    assert client.calls[-1]["tools"] is None
    assert client.calls[-2]["tools"] is not None


def test_loop_no_tools_returns_direct_answer():
    client = _FakeChatClient([_turn("Direct answer, no tools needed.")])
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hello"}],
        client,
        repo_path="/r",
        registry=None,
    )
    assert out["reply"] == "Direct answer, no tools needed."
    assert out["tool_calls"] == []
    # With no registry the model is offered no tools.
    assert client.calls[0]["tools"] is None


# -- graceful degradation (never a 500) ---------------------------------------


def test_degrades_when_client_unavailable():
    client = _FakeChatClient([], available=False)
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}], client, repo_path="/r", registry=None
    )
    assert out["reply"] == chat_mod._UNAVAILABLE_REPLY
    assert out["tool_calls"] == []
    assert out["model"].startswith("Meta Muse")
    assert client.calls == []  # never even called


def test_degrades_when_client_is_none():
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}], None, repo_path="/r", registry=None
    )
    assert out["reply"] == chat_mod._UNAVAILABLE_REPLY


def test_degrades_gracefully_on_transport_failure_mid_loop():
    # First (and only) turn is None -> transport failure; no tools ran.
    client = _FakeChatClient([None])
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}], client, repo_path="/r", registry=None
    )
    assert out["reply"] == chat_mod._PARTIAL_REPLY
    assert out["tool_calls"] == []


def test_degraded_reply_names_tools_that_ran():
    registry = ([], {"vscan_audit": (lambda p: json.dumps({"counts": {}}), _FakeInput)})
    # Tool runs in round 1; round 2 (the model's next turn) fails transport.
    client = _FakeChatClient(
        [_turn(None, [_tool_call("vscan_audit", "{}")]), None]
    )
    out = chat_mod.run_chat(
        [{"role": "user", "content": "hi"}], client, repo_path="/r", registry=registry
    )
    assert out["reply"].startswith(chat_mod._PARTIAL_REPLY)
    assert "vscan_audit" in out["reply"]
    assert out["tool_calls"][0]["ok"] is True


# -- execute_tool + summaries (units) -----------------------------------------


def test_execute_tool_injects_repo_path_and_strips_refresh():
    captured: dict[str, Any] = {}

    def fake(params: _FakeInput) -> str:
        captured.update(params.received)
        return "{}"

    ok, result = chat_mod.execute_tool(
        fake, _FakeInput, {"refresh": True, "query": "x"}, "/warm"
    )
    assert ok is True
    assert captured["repo_path"] == "/warm"
    assert captured["query"] == "x"
    assert "refresh" not in captured  # scan-mutating field is never forwarded


def test_execute_tool_strips_offline():
    # Even if the model smuggles ``offline`` through, execute_tool drops it so it
    # can never force the empty offline result set (a false-safe). The legit
    # query field survives and repo_path is injected server-side.
    captured: dict[str, Any] = {}

    def fake(params: _FakeInput) -> str:
        captured.update(params.received)
        return "{}"

    ok, _ = chat_mod.execute_tool(
        fake, _FakeInput, {"offline": True, "dep_id": "dep:PyPI:PyYAML"}, "/warm"
    )
    assert ok is True
    assert captured["repo_path"] == "/warm"
    assert captured["dep_id"] == "dep:PyPI:PyYAML"
    assert "offline" not in captured  # result-narrowing field is never forwarded


def test_execute_tool_reports_invalid_args():
    ok, result = chat_mod.execute_tool(lambda p: "{}", _RaisingInput, {"x": 1}, "/r")
    assert ok is False
    assert result.startswith("Error: invalid arguments")


def test_execute_tool_treats_tool_error_string_as_failure():
    ok, result = chat_mod.execute_tool(
        lambda p: "Error: dependency not found", _FakeInput, {}, "/r"
    )
    assert ok is False
    assert result == "Error: dependency not found"


def test_summarize_tool_result_error_passthrough():
    assert (
        chat_mod.summarize_tool_result("vscan_audit", False, "Error: boom")
        == "Error: boom"
    )


def test_summarize_finding_detail_counts_proven_taint():
    payload = json.dumps(
        {
            "dependency": "PyYAML",
            "verdict": "confirmed",
            "cves": [{"taint": "tainted"}, {"taint": None}],
        }
    )
    summary = chat_mod.summarize_tool_result("vscan_finding_detail", True, payload)
    assert "PyYAML" in summary
    assert "1 with a proven taint path" in summary


# -- the real exposed registry (needs the optional mcp dep) -------------------


def test_real_registry_exposes_only_the_eight_read_only_tools():
    pytest.importorskip("mcp")
    registry = chat_mod.build_registry()
    assert registry is not None
    schemas, dispatch = registry

    names = {s["function"]["name"] for s in schemas}
    assert names == {
        "vscan_scan_overview",
        "vscan_find",
        "vscan_describe",
        "vscan_call_graph",
        "vscan_trace_entrypoint",
        "vscan_dep_reachers",
        "vscan_audit",
        "vscan_finding_detail",
    }
    # No mutating / refresh / fix tool is ever exposed.
    assert "vscan_apply_upgrade" not in names
    assert "vscan_verify_fix" not in names
    assert "vscan_remediation" not in names
    assert "vscan_diff" not in names

    # Every exposed schema hides repo_path, refresh and offline (the last two
    # would change the result set / force an empty offline finding set).
    for schema in schemas:
        props = schema["function"]["parameters"]["properties"]
        assert "repo_path" not in props
        assert "refresh" not in props
        assert "offline" not in props
    assert set(dispatch) == names
