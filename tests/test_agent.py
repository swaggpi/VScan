"""Agent-layer tests -- MUST NOT touch the network or require an API key.

The knowledge graph comes from the real, deterministic, offline ``scan_repo``
over ``samples/vulnerable-app``; reachability is the real pure computation.
Findings are constructed directly (never fetched from OSV), and the LLM client
is either forced offline or replaced with a canned stub, so no request is ever
issued. These exercise:

* the LLM path (mocked) producing structured Assessments on reachable findings;
* the deterministic offline heuristic citing the sample README's "any user";
* the hard guardrail: the pass mutates neither the graph, the reachability
  result, nor any finding's ``reachable`` flag, and every result is advisory;
* ``LLMClient.available()`` being false when the env vars are unset.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from scanner.agent import Assessment, LLMClient, assess_findings
from scanner.correlate import Finding
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)

PYYAML_ID = "dep:PyPI:PyYAML"
URLLIB3_ID = "dep:PyPI:urllib3"
PYYAML_CVE = "CVE-2020-1747"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


def _pyyaml_finding() -> Finding:
    """A finding for the reachable PyYAML dependency (POST /import -> y.load)."""
    return Finding(
        dependency_id=PYYAML_ID,
        dependency_name="PyYAML",
        version="3.13",
        ecosystem="PyPI",
        vuln_id="GHSA-pyyaml-3pqx",
        cve_ids=[PYYAML_CVE],
        summary="PyYAML load() allows arbitrary code execution.",
        fixed_versions=["5.3.1"],
        severity="CRITICAL",
    )


def _urllib3_finding() -> Finding:
    """A finding for a declared-but-unreachable dependency (negative case)."""
    return Finding(
        dependency_id=URLLIB3_ID,
        dependency_name="urllib3",
        version="1.24.1",
        ecosystem="PyPI",
        vuln_id="GHSA-urllib3-xxxx",
        cve_ids=["CVE-2019-11324"],
        summary="urllib3 certificate verification issue.",
        fixed_versions=["1.24.2"],
        severity="HIGH",
    )


class _StubClient:
    """A canned OpenAI-compatible client stub (duck-typed for assess_findings)."""

    def __init__(self, payload: dict[str, Any] | None):
        self._payload = payload
        self.calls = 0

    def available(self) -> bool:
        return True

    def complete_json(self, system_prompt: str, user_prompt: str):
        self.calls += 1
        # The reaching route context must be handed to the model.
        assert "POST /import" in user_prompt
        return self._payload


# -- LLM path (mocked) --------------------------------------------------------


def test_llm_path_produces_structured_assessment(graph, reach):
    client = _StubClient(
        {
            "exposure": "internet-facing",
            "authentication": "none",
            "rationale": "The /import route is documented as accepting uploads "
            "from any user.",
            "summary": "Publicly reachable YAML deserialization RCE.",
        }
    )
    assessments = assess_findings(
        graph, [_pyyaml_finding()], reach, client=client
    )

    assert client.calls == 1
    assert len(assessments) == 1
    a = assessments[0]
    assert isinstance(a, Assessment)
    assert a.dependency_id == PYYAML_ID
    assert a.cve == PYYAML_CVE
    assert a.exposure == "internet-facing"
    assert a.authentication == "none"
    assert a.provenance == "llm"
    assert a.advisory is True
    assert "POST /import" in a.reaching_entrypoints
    assert a.rationale and a.summary


def test_llm_garbage_values_collapse_to_unknown(graph, reach):
    # A model that returns out-of-vocabulary verdicts must not leak them through.
    client = _StubClient(
        {"exposure": "maybe", "authentication": "sort-of", "rationale": "x",
         "summary": "y"}
    )
    assessments = assess_findings(graph, [_pyyaml_finding()], reach, client=client)
    a = assessments[0]
    assert a.exposure == "unknown"
    assert a.authentication == "unknown"
    assert a.provenance == "llm"


def test_llm_error_falls_back_to_offline(graph, reach):
    # complete_json returning None (any client error) must fall back offline.
    client = _StubClient(None)
    assessments = assess_findings(graph, [_pyyaml_finding()], reach, client=client)
    a = assessments[0]
    assert a.provenance == "offline-heuristic"
    assert a.advisory is True


# -- offline heuristic --------------------------------------------------------


def test_offline_heuristic_cites_readme_any_user(graph, reach):
    assessments = assess_findings(
        graph, [_pyyaml_finding()], reach, client=LLMClient.disabled()
    )
    assert len(assessments) == 1
    a = assessments[0]
    assert a.dependency_id == PYYAML_ID
    assert a.exposure == "internet-facing"
    assert a.authentication == "none"
    assert a.provenance == "offline-heuristic"
    assert a.advisory is True
    assert "any user" in a.rationale
    assert "POST /import" in a.reaching_entrypoints


def test_offline_only_reachable_findings_are_assessed(graph, reach):
    # urllib3 is declared but unreachable; it must be dropped, PyYAML kept.
    assessments = assess_findings(
        graph,
        [_pyyaml_finding(), _urllib3_finding()],
        reach,
        client=LLMClient.disabled(),
    )
    ids = {a.dependency_id for a in assessments}
    assert ids == {PYYAML_ID}


def test_offline_dep_fallback_when_no_findings(graph, reach):
    # With no advisory findings, the exposure layer still runs over reachable
    # deps (cve=None) so the feature works end-to-end offline.
    assessments = assess_findings(graph, [], reach, client=LLMClient.disabled())
    ids = {a.dependency_id for a in assessments}
    assert PYYAML_ID in ids
    pyyaml = next(a for a in assessments if a.dependency_id == PYYAML_ID)
    assert pyyaml.cve is None
    assert pyyaml.exposure == "internet-facing"
    assert pyyaml.provenance == "offline-heuristic"


# -- hard guardrail -----------------------------------------------------------


def test_guardrail_pass_mutates_nothing(graph, reach):
    findings = [_pyyaml_finding(), _urllib3_finding()]

    graph_before = graph.to_dict()
    reach_before = reach.to_dict()
    reachable_before = [f.reachable for f in findings]
    paths_before = [list(f.example_path) for f in findings]
    eps_before = [list(f.reachable_entrypoints) for f in findings]

    assessments = assess_findings(
        graph, findings, reach, client=LLMClient.disabled()
    )

    # The graph is untouched: no node/edge added or modified.
    assert graph.to_dict() == graph_before
    # The reachability result is untouched.
    assert reach.to_dict() == reach_before
    # No finding's reachability fields were mutated (not even set True).
    assert [f.reachable for f in findings] == reachable_before == [False, False]
    assert [list(f.example_path) for f in findings] == paths_before
    assert [list(f.reachable_entrypoints) for f in findings] == eps_before
    # Every assessment is advisory and lives in a labelled provenance tier.
    assert assessments
    for a in assessments:
        assert a.advisory is True
        assert a.provenance in {"llm", "offline-heuristic"}
        assert "does not" in a.note.lower() or "does NOT" in a.note


def test_guardrail_holds_on_llm_path_too(graph, reach):
    findings = [_pyyaml_finding()]
    reachable_before = [f.reachable for f in findings]
    client = _StubClient(
        {"exposure": "internal", "authentication": "required", "rationale": "r",
         "summary": "s"}
    )
    assessments = assess_findings(graph, findings, reach, client=client)
    assert [f.reachable for f in findings] == reachable_before == [False]
    assert all(a.advisory is True for a in assessments)


# -- client configuration -----------------------------------------------------


def test_available_is_false_when_env_unset(monkeypatch):
    for var in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert LLMClient().available() is False


def test_available_is_true_when_all_env_set(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    client = LLMClient()
    assert client.available() is True
    # Trailing slash stripped; endpoint composed from the version-qualified base.
    assert client.base_url == "https://example.invalid/v1"


def test_disabled_client_is_never_available():
    assert LLMClient.disabled().available() is False


def test_complete_json_returns_none_when_unavailable():
    # No network call is attempted when the client is not configured.
    assert LLMClient.disabled().complete_json("sys", "user") is None
