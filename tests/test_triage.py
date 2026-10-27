"""Symbol-level exploitability triage tests -- MUST NOT touch the network.

The knowledge graph comes from the real, deterministic, offline ``scan_repo``
over ``samples/vulnerable-app`` (PyYAML is called via ``yaml.load`` and is
reachable; Flask is reachable with unresolved calls into it; urllib3 is declared
but unreachable); reachability is the real pure computation. Findings are
constructed directly (never fetched from OSV) with hand-written CVE summaries,
and the LLM client is either forced offline or replaced with a canned stub, so
no request is ever issued. These exercise:

* AFFECTED when a called symbol is the CVE's named sink (``yaml.load``);
* LIKELY_UNAFFECTED only under the strong basis (CVE names a different function,
  it is absent from the called set, and no unresolved calls into the dep);
* the no-false-security property: ambiguity / unresolved calls / no named
  function all yield UNCERTAIN, never LIKELY_UNAFFECTED -- enforced on the
  offline heuristic AND on model output (out-of-vocab -> uncertain, and a model
  "likely_unaffected" is downgraded unless the basis holds);
* the hard guardrail: the pass mutates neither the graph, the reachability
  result, nor any finding, and every result is advisory.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

import json

from scanner.agent import LLMClient, Triage, triage_findings
from scanner.agent.triage import _offline_triage
from scanner.cli import main
from scanner.correlate import Finding
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)

PYYAML_ID = "dep:PyPI:PyYAML"
FLASK_ID = "dep:PyPI:Flask"
URLLIB3_ID = "dep:PyPI:urllib3"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


def _pyyaml_finding(summary: str, *, cve: str = "CVE-2020-14343") -> Finding:
    """A reachable PyYAML finding (the project calls yaml.load) with a given CVE."""
    return Finding(
        dependency_id=PYYAML_ID,
        dependency_name="PyYAML",
        version="3.13",
        ecosystem="PyPI",
        vuln_id="GHSA-pyyaml-3pqx",
        cve_ids=[cve],
        summary=summary,
        fixed_versions=["5.3.1"],
        severity="CRITICAL",
    )


def _flask_finding(summary: str) -> Finding:
    """A reachable Flask finding (callers into Flask have unresolved calls)."""
    return Finding(
        dependency_id=FLASK_ID,
        dependency_name="Flask",
        version="0.12",
        ecosystem="PyPI",
        vuln_id="GHSA-flask-xxxx",
        cve_ids=["CVE-2019-1010083"],
        summary=summary,
        fixed_versions=["1.0"],
        severity="HIGH",
    )


def _urllib3_finding() -> Finding:
    """A declared-but-unreachable finding (negative case)."""
    return Finding(
        dependency_id=URLLIB3_ID,
        dependency_name="urllib3",
        version="1.24.1",
        ecosystem="PyPI",
        vuln_id="GHSA-urllib3-xxxx",
        cve_ids=["CVE-2019-11324"],
        summary="urllib3 Retry handling allows redirect to a different host.",
        fixed_versions=["1.24.2"],
        severity="HIGH",
    )


class _StubClient:
    """A canned OpenAI-compatible client stub (duck-typed for triage_findings)."""

    def __init__(self, payload: dict[str, Any] | None):
        self._payload = payload
        self.calls = 0
        self.last_user_prompt = ""

    def available(self) -> bool:
        return True

    def complete_json(self, system_prompt: str, user_prompt: str):
        self.calls += 1
        self.last_user_prompt = user_prompt
        return self._payload


# -- offline heuristic: the three verdicts ------------------------------------


def test_affected_when_called_symbol_is_the_cve_sink(graph, reach):
    # CVE names yaml.load; the project calls yaml.load -> AFFECTED.
    finding = _pyyaml_finding(
        "PyYAML yaml.load() permits arbitrary code execution when loading "
        "untrusted YAML input."
    )
    result = triage_findings(graph, [finding], reach, client=LLMClient.disabled())
    assert len(result) == 1
    t = result[0]
    assert t.dependency_id == PYYAML_ID
    assert t.called_symbols == ["yaml.load"]
    assert t.affected == "affected"
    assert t.confidence == "high"
    assert "yaml.load" in t.rationale
    assert t.provenance == "offline-heuristic"
    assert t.advisory is True


def test_likely_unaffected_when_cve_names_absent_function(graph, reach):
    # CVE names yaml.full_load (NOT called; the project calls yaml.load), and
    # there are no unresolved calls into PyYAML -> LIKELY_UNAFFECTED.
    finding = _pyyaml_finding(
        "A flaw in PyYAML's yaml.full_load constructor allows code execution via "
        "crafted python/object/apply tags."
    )
    result = triage_findings(graph, [finding], reach, client=LLMClient.disabled())
    t = result[0]
    assert t.unresolved_calls_into_dependency is False
    assert t.affected == "likely_unaffected"
    assert "yaml.load" in t.called_symbols
    assert "full_load" in t.rationale


def test_uncertain_when_no_named_function(graph, reach):
    # The CVE names no specific function to compare against -> UNCERTAIN, and it
    # must NOT be declared safe (no false security).
    finding = _pyyaml_finding(
        "This dependency has a vulnerability that permits denial of service "
        "under certain configurations."
    )
    t = triage_findings(graph, [finding], reach, client=LLMClient.disabled())[0]
    assert t.affected == "uncertain"
    assert t.affected != "likely_unaffected"


def test_uncertain_when_unresolved_calls_present_even_if_function_named(graph, reach):
    # Flask has unresolved calls into it. Even though the CVE names a specific
    # function absent from the called set, the incomplete usage view forbids a
    # "safe" verdict -> UNCERTAIN, never LIKELY_UNAFFECTED.
    finding = _flask_finding(
        "The framework mishandles the Session.save_session cookie signing, "
        "enabling tampering."
    )
    t = triage_findings(graph, [finding], reach, client=LLMClient.disabled())[0]
    assert t.unresolved_calls_into_dependency is True
    assert t.affected == "uncertain"
    assert t.affected != "likely_unaffected"


def test_offline_is_deterministic(graph, reach):
    finding = _pyyaml_finding("PyYAML yaml.load() allows code execution.")
    first = triage_findings(graph, [finding], reach, client=LLMClient.disabled())
    second = triage_findings(graph, [finding], reach, client=LLMClient.disabled())
    assert [t.to_dict() for t in first] == [t.to_dict() for t in second]


def test_only_reachable_findings_are_triaged(graph, reach):
    # urllib3 is declared but unreachable; it must be dropped. There is no
    # dependency-only fallback -- triage needs a CVE to compare against.
    result = triage_findings(
        graph,
        [_pyyaml_finding("yaml.load RCE"), _urllib3_finding()],
        reach,
        client=LLMClient.disabled(),
    )
    assert {t.dependency_id for t in result} == {PYYAML_ID}


def test_empty_when_no_reachable_findings(graph, reach):
    assert triage_findings(graph, [], reach, client=LLMClient.disabled()) == []


# -- LLM path (mocked) + the conservative gate on model output ----------------


def test_llm_path_produces_structured_triage(graph, reach):
    client = _StubClient(
        {
            "affected": "affected",
            "confidence": "high",
            "rationale": "The project calls yaml.load, the vulnerable sink.",
        }
    )
    finding = _pyyaml_finding("PyYAML yaml.load() RCE.")
    t = triage_findings(graph, [finding], reach, client=client)[0]
    assert t.provenance == "llm"
    assert t.affected == "affected"
    assert t.confidence == "high"
    # The deterministic called-symbol context is handed to the model.
    assert "yaml.load" in client.last_user_prompt


def test_out_of_vocab_model_verdict_collapses_to_uncertain(graph, reach):
    client = _StubClient(
        {"affected": "totally_safe", "confidence": "super", "rationale": "r"}
    )
    finding = _pyyaml_finding("PyYAML yaml.full_load issue.")
    t = triage_findings(graph, [finding], reach, client=client)[0]
    assert t.affected == "uncertain"
    assert t.confidence == "low"  # out-of-vocab confidence -> conservative default


def test_model_likely_unaffected_downgraded_when_symbol_matches(graph, reach):
    # A model that claims "safe" while a called symbol IS the sink must be
    # corrected to AFFECTED -- never left as a false safe.
    client = _StubClient(
        {"affected": "likely_unaffected", "confidence": "high", "rationale": "r"}
    )
    finding = _pyyaml_finding("PyYAML yaml.load() is the vulnerable sink.")
    t = triage_findings(graph, [finding], reach, client=client)[0]
    assert t.affected == "affected"


def test_model_likely_unaffected_downgraded_when_ambiguous(graph, reach):
    # A model that claims "safe" with no specific function named must be
    # downgraded to UNCERTAIN (the basis for a safe verdict is absent).
    client = _StubClient(
        {"affected": "likely_unaffected", "confidence": "high", "rationale": "r"}
    )
    finding = _pyyaml_finding("Denial of service under certain configurations.")
    t = triage_findings(graph, [finding], reach, client=client)[0]
    assert t.affected == "uncertain"


def test_llm_error_falls_back_to_offline(graph, reach):
    # complete_json returning None (any client error) falls back to the offline
    # verdict, which still finds the yaml.load match.
    client = _StubClient(None)
    finding = _pyyaml_finding("PyYAML yaml.load() RCE.")
    t = triage_findings(graph, [finding], reach, client=client)[0]
    assert t.provenance == "offline-heuristic"
    assert t.affected == "affected"


# -- hard guardrail -----------------------------------------------------------


def test_guardrail_pass_mutates_nothing(graph, reach):
    findings = [
        _pyyaml_finding("PyYAML yaml.load() RCE."),
        _flask_finding("Flask Session.save_session tampering."),
        _urllib3_finding(),
    ]

    graph_before = graph.to_dict()
    reach_before = reach.to_dict()
    reachable_before = [f.reachable for f in findings]
    summaries_before = [f.summary for f in findings]

    result = triage_findings(graph, findings, reach, client=LLMClient.disabled())

    assert graph.to_dict() == graph_before
    assert reach.to_dict() == reach_before
    # No finding was mutated (reachability flags untouched, not even set True).
    assert [f.reachable for f in findings] == reachable_before == [False, False, False]
    assert [f.summary for f in findings] == summaries_before
    # Every triage is advisory, in a labelled provenance tier, and restates the
    # guardrail in its note.
    assert result
    for t in result:
        assert isinstance(t, Triage)
        assert t.advisory is True
        assert t.provenance in {"llm", "offline-heuristic"}
        assert "does not" in t.note.lower()
        assert t.affected in {"affected", "likely_unaffected", "uncertain"}
        assert t.confidence in {"low", "medium", "high"}


def test_offline_triage_helper_matches_pass(graph, reach):
    # The module helper and the public pass agree on the offline verdict.
    finding = _pyyaml_finding("PyYAML yaml.load() RCE.")
    direct = _offline_triage(finding, ["yaml.load"], False, finding.summary)
    assert direct.affected == "affected"
    assert direct.provenance == "offline-heuristic"


# -- CLI wiring ---------------------------------------------------------------


def test_cli_bundle_includes_triage_key(tmp_path, capsys):
    # `audit --bundle` always carries the advisory triage tier (offline here).
    bundle_path = tmp_path / "bundle.json"
    rc = main(["audit", SAMPLE_APP, "--offline", "--bundle", str(bundle_path)])
    assert rc == 0
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert "triage" in bundle and isinstance(bundle["triage"], list)


def test_cli_audit_json_gains_triage_key(tmp_path, capsys):
    out_path = tmp_path / "audit.json"
    rc = main(["audit", SAMPLE_APP, "--offline", "--json", "-o", str(out_path)])
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "triage" in payload and isinstance(payload["triage"], list)


def test_cli_default_text_output_has_no_triage_section(capsys):
    # The default audit TEXT output (no flags) is unchanged: no triage section.
    rc = main(["audit", SAMPLE_APP, "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Exploitability triage" not in out


def test_cli_explain_prints_triage_section(capsys):
    rc = main(["audit", SAMPLE_APP, "--offline", "--explain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Exploitability triage (advisory tier)" in out
