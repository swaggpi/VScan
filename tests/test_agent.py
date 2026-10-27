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
import re
import threading
import time
from typing import Any

import pytest

from scanner.agent import Assessment, LLMClient, assess_findings
from scanner.agent.assess import (
    _INTERNAL_PHRASES,
    _NOAUTH_PHRASES,
    _PUBLIC_PHRASES,
    _find_phrase,
)
from scanner.cli import _oneline
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


# -- bounded-concurrency LLM path (mocked, no network) ------------------------


def _pyyaml_findings(n: int) -> list[Finding]:
    """`n` findings for the (reachable) PyYAML dep, with ascending CVE ids.

    All share PyYAML's dependency id, so each is a distinct reachable subject
    assessed by its own ``complete_json`` call. The ids are ascending so the
    deterministic output sort (by dependency_name, cve, dependency_id) leaves
    them in input order -- letting the test assert order is preserved.
    """
    return [
        Finding(
            dependency_id=PYYAML_ID,
            dependency_name="PyYAML",
            version="3.13",
            ecosystem="PyPI",
            vuln_id=f"GHSA-pyyaml-{i:04d}",
            cve_ids=[f"CVE-2020-{i:04d}"],
            summary="PyYAML load() allows arbitrary code execution.",
            fixed_versions=["5.3.1"],
            severity="CRITICAL",
        )
        for i in range(n)
    ]


def _cve_from_prompt(user_prompt: str) -> str:
    match = re.search(r"cve: (\S+)", user_prompt)
    return match.group(1) if match else "?"


class _ConcurrentClient:
    """Mock client recording call count, peak concurrency, completion order.

    Each call sleeps so overlapping calls are observable; earlier-arriving calls
    sleep longer, skewing completion order away from input order to prove the
    output order does not follow thread completion.
    """

    def __init__(self, n: int):
        self._n = n
        self._lock = threading.Lock()
        self._active = 0
        self.peak_concurrency = 0
        self.calls = 0
        self.completion_order: list[str] = []

    def available(self) -> bool:
        return True

    def complete_json(self, system_prompt: str, user_prompt: str):
        assert "POST /import" in user_prompt
        cve = _cve_from_prompt(user_prompt)
        with self._lock:
            self.calls += 1
            arrival = self.calls
            self._active += 1
            self.peak_concurrency = max(self.peak_concurrency, self._active)
        time.sleep(0.02 * (self._n - arrival + 1))
        with self._lock:
            self._active -= 1
            self.completion_order.append(cve)
        return {
            "exposure": "internet-facing",
            "authentication": "none",
            "rationale": f"route context for {cve}",
            "summary": f"summary for {cve}",
        }


class _FlakyClient:
    """Mock client where one subject raises and one returns None."""

    def __init__(self, fail_cve: str, none_cve: str, payload: dict[str, Any]):
        self._fail_cve = fail_cve
        self._none_cve = none_cve
        self._payload = payload
        self._lock = threading.Lock()
        self.calls = 0

    def available(self) -> bool:
        return True

    def complete_json(self, system_prompt: str, user_prompt: str):
        cve = _cve_from_prompt(user_prompt)
        with self._lock:
            self.calls += 1
        if cve == self._fail_cve:
            raise RuntimeError("simulated model/transport error")
        if cve == self._none_cve:
            return None
        return self._payload


def test_llm_calls_run_concurrently_and_preserve_order(graph, reach):
    # Several reachable findings: the per-subject model calls run in parallel,
    # yet every subject is assessed and the output order is deterministic.
    findings = _pyyaml_findings(5)
    client = _ConcurrentClient(len(findings))

    assessments = assess_findings(graph, findings, reach, client=client)

    assert client.calls == len(findings)
    assert len(assessments) == len(findings)
    # Every subject got its own llm result.
    assert all(a.provenance == "llm" for a in assessments)
    assert all(a.advisory is True for a in assessments)
    # Output order matches the input order (independent of completion order).
    assert [a.cve for a in assessments] == [f.cve_ids[0] for f in findings]
    # The calls actually overlapped -- the pool ran them concurrently.
    assert client.peak_concurrency >= 2


def test_one_subject_failure_does_not_break_the_others(graph, reach):
    # A worker that raises OR returns None must fall back to offline for that
    # subject only; the others still get their llm result and nothing raises.
    findings = _pyyaml_findings(4)
    cves = [f.cve_ids[0] for f in findings]
    client = _FlakyClient(
        fail_cve=cves[1],
        none_cve=cves[2],
        payload={
            "exposure": "internet-facing",
            "authentication": "none",
            "rationale": "documented as reachable from any user",
            "summary": "publicly reachable RCE",
        },
    )

    # Must not raise out of assess_findings.
    assessments = assess_findings(graph, findings, reach, client=client)

    assert len(assessments) == len(findings)
    by_cve = {a.cve: a for a in assessments}
    assert by_cve[cves[0]].provenance == "llm"
    assert by_cve[cves[1]].provenance == "offline-heuristic"  # raised -> fallback
    assert by_cve[cves[2]].provenance == "offline-heuristic"  # None -> fallback
    assert by_cve[cves[3]].provenance == "llm"
    # Guardrail intact for every subject regardless of path taken.
    assert all(a.advisory is True for a in assessments)
    assert all(
        a.provenance in {"llm", "offline-heuristic"} for a in assessments
    )


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


# -- advisory-output defect fixes (regression) --------------------------------


def test_offline_dep_fallback_does_not_label_cleandep_vulnerable(graph, reach):
    # #13a: with no findings, the dep-fallback must NOT describe a finding-less
    # dependency as "vulnerable" / "externally exploitable" -- there is no CVE.
    assessments = assess_findings(graph, [], reach, client=LLMClient.disabled())
    assert assessments  # the fallback still runs over reachable deps
    for a in assessments:
        assert a.cve is None and a.vuln_id is None
        blob = f"{a.summary} {a.rationale}".lower()
        assert "vulnerable" not in blob
        assert "externally exploitable" not in blob
        assert "no advisory matched" in a.summary.lower()


def test_model_output_cannot_forge_report_lines():
    # #13b: a model (or injected doc text it echoes) returning newlines must not
    # be able to forge a "    REACHABLE via ..." line in the --explain render.
    spoof = "looks fine\n    REACHABLE via /evil" + " filler" * 100
    a = Assessment(
        dependency_id="dep:PyPI:Evil",
        dependency_name="Evil",
        cve=None,
        vuln_id="GHSA-evil",
        exposure="unknown",
        authentication="unknown",
        rationale=spoof,
        summary="summary\n    REACHABLE via /also-evil",
        provenance="llm",
    )
    rendered_rationale = _oneline(a.rationale)
    rendered_summary = _oneline(a.summary)
    # Collapsed to a single line -- no newline can introduce a forged line.
    assert "\n" not in rendered_rationale
    assert "\n" not in rendered_summary
    assert not rendered_rationale.lstrip().startswith("REACHABLE")
    # Long content is truncated with the ellipsis marker.
    assert rendered_rationale.endswith("…")
    assert len(rendered_rationale) <= 300


def test_heuristic_negation_guard_blocks_not_public():
    # #13c: "NOT public" / "not internet-facing" must not be read as public.
    assert _find_phrase("This endpoint is NOT public.", _PUBLIC_PHRASES) is None
    assert _find_phrase("The service is not internet-facing.", _PUBLIC_PHRASES) is None


def test_heuristic_word_boundary_admin_not_in_administer():
    # #13c: a bare "administer" must not match the whole-word "admin" -> internal.
    assert _find_phrase("Staff may administer the cluster.", _INTERNAL_PHRASES) is None


def test_heuristic_genuine_any_user_still_matches():
    # #13c: a real "any user" phrase must still classify as public / no-auth.
    text = "The endpoint accepts uploads from any user."
    assert _find_phrase(text, _PUBLIC_PHRASES) == "any user"
    assert _find_phrase(text, _NOAUTH_PHRASES) == "any user"
