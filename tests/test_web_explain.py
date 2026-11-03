"""Tests for the ``/api/explain`` backend -- grounding, fallback, HTTP shapes.

These never touch the network or require an API key: the LLM client is either a
canned stub or forced unavailable, and the scan state is populated directly with
hand-built finding dicts (shaped exactly like
:func:`scanner.correlate.report.audit` findings -- ``asdict`` of a Finding plus
the three-way ``verdict`` key). They exercise:

* the response verdict tiers derived from ``taint`` / ``reachable``;
* the deterministic offline rendering being grounded per tier (and never
  claiming exploitability for a merely-reachable finding);
* the LLM path producing ``provenance == "llm"`` and falling back to
  ``"offline-heuristic"`` on an unavailable / invalid / raising client;
* the branded ``model`` label; and
* the 200 / 404 / 503 routing of the endpoint itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from scanner.web import explain as explain_mod


def _exploitable() -> dict[str, Any]:
    return {
        "dependency_id": "dep:PyPI:PyYAML",
        "dependency_name": "PyYAML",
        "version": "5.3",
        "ecosystem": "PyPI",
        "vuln_id": "GHSA-6757-jp84-gxfx",
        "cve_ids": ["CVE-2020-1747"],
        "summary": "Arbitrary code execution via full_load",
        "fixed_versions": ["5.4", "6.0"],
        "details": "yaml.load with the default loader allows arbitrary code execution.",
        "severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True,
        "epss": 0.9,
        "reachable": True,
        "reachable_entrypoints": ["GET /items"],
        "example_path": ["ep:GET:/items", "fn:handler", "yaml.load"],
        "reached_symbols": ["yaml.load"],
        "symbol_match": "confirmed",
        "taint": "tainted",
        "taint_evidence": {
            "verdict": "tainted",
            "source": "request.body",
            "sink_symbol": "yaml.load",
            "entrypoint": "GET /items",
            "path": ["GET /items", "handler", "yaml.load"],
        },
        "verdict": "reachable",
    }


def _reachable() -> dict[str, Any]:
    finding = _exploitable()
    finding["taint"] = "not_proven"
    finding["taint_evidence"] = None
    finding["vuln_id"] = "GHSA-reachable"
    return finding


def _not_reached() -> dict[str, Any]:
    finding = _reachable()
    finding["reachable"] = False
    finding["reachable_entrypoints"] = []
    finding["example_path"] = []
    finding["vuln_id"] = "GHSA-notreached"
    return finding


class _StubClient:
    """Canned, duck-typed LLM client (``available`` + ``complete_json``)."""

    def __init__(self, payload: Any, *, available: bool = True, raises: bool = False):
        self._payload = payload
        self._available = available
        self._raises = raises
        self.calls: list[tuple[str, str]] = []

    def available(self) -> bool:
        return self._available

    def complete_json(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        if self._raises:
            raise RuntimeError("boom")
        return self._payload


# -- verdict tiers ------------------------------------------------------------


def test_response_verdict_tiers():
    assert explain_mod.response_verdict(_exploitable()) == "exploitable"
    assert explain_mod.response_verdict(_reachable()) == "reachable"
    assert explain_mod.response_verdict(_not_reached()) == "not_reached"


# -- offline grounding --------------------------------------------------------


def test_offline_exploitable_narrates_proven_taint_path():
    narrative, remediation = explain_mod.offline_explanation(
        _exploitable(), "exploitable"
    )
    assert "GET /items -> handler -> yaml.load" in narrative
    assert "yaml.load" in narrative and "request.body" in narrative
    assert "5.4" in remediation  # concrete upgrade from fixed_versions


def test_offline_reachable_does_not_claim_exploitable():
    narrative, remediation = explain_mod.offline_explanation(_reachable(), "reachable")
    lowered = narrative.lower()
    assert "reachable" in lowered
    assert "not proven" in lowered or "not_proven" in lowered or "unconfirmed" in lowered
    # It must not assert a proven/confirmed exploit for the reachable tier.
    assert "proven to flow" not in lowered
    assert "5.4" in remediation


def test_offline_not_reached_states_reachability_not_safety():
    # Honesty: the not-reached narrative makes a REACHABILITY statement and a
    # lower-bound caveat -- it must never assert the finding is "not exploitable"
    # (static non-reachability is not a proof of safety).
    narrative, _ = explain_mod.offline_explanation(_not_reached(), "not_reached")
    lowered = narrative.lower()
    assert "not exploitable" not in lowered
    assert "reach" in lowered  # it is phrased as reachability, not exploitability
    assert "lower bound" in lowered or "not a proof of safety" in lowered


def test_offline_remediation_handles_missing_fixed_versions():
    finding = _exploitable()
    finding["fixed_versions"] = []
    _, remediation = explain_mod.offline_explanation(finding, "exploitable")
    assert "no fixed version" in remediation.lower()


# -- llm path + fallback ------------------------------------------------------


def test_llm_path_sets_provenance_and_uses_facts():
    client = _StubClient({"narrative": "N", "remediation": "R"})
    finding = _exploitable()
    out = explain_mod.explain_finding(finding, client)
    assert out["provenance"] == "llm"
    assert out["narrative"] == "N" and out["remediation"] == "R"
    # The model was handed the finding's real facts, grounded.
    _system, user = client.calls[0]
    assert "yaml.load" in user and "CVE-2020-1747" in user


@pytest.mark.parametrize(
    "client",
    [
        _StubClient(None, available=True),
        _StubClient({"narrative": "", "remediation": None}, available=True),
        _StubClient({"narrative": "ok"}, available=True),  # missing remediation
        _StubClient("not a dict", available=True),
        _StubClient({"narrative": "N", "remediation": "R"}, available=False),
        _StubClient(None, available=True, raises=True),
    ],
)
def test_fallback_to_offline_on_bad_or_unavailable_client(client):
    out = explain_mod.explain_finding(_reachable(), client)
    assert out["provenance"] == "offline-heuristic"
    assert out["narrative"] and out["remediation"]


# -- negation-aware exploitability guard (cardinal rule) ----------------------


def test_guard_discards_llm_overclaim_for_reachable():
    # The model over-claims exploitability on a merely-reachable finding; the
    # guard must discard the LLM prose and fall back to the grounded offline
    # rendering (provenance "offline-heuristic"), which never affirms exploit.
    client = _StubClient(
        {
            "narrative": "This finding is exploitable: a proven taint path "
            "reaches yaml.load.",
            "remediation": "Upgrade PyYAML to 5.4.",
        }
    )
    out = explain_mod.explain_finding(_reachable(), client)
    assert out["provenance"] == "offline-heuristic"
    lowered = out["narrative"].lower()
    assert "reachable" in lowered
    assert "not proven" in lowered or "unconfirmed" in lowered
    # The model's affirmative over-claim is gone.
    assert "a proven taint path reaches yaml.load" not in lowered


def test_guard_keeps_correct_reachable_llm_narrative():
    # A correct reachable narrative ("reachable but NOT proven exploitable")
    # must NOT trip the guard -- the LLM rendering is kept (provenance "llm").
    narrative = "The vulnerable code is reachable but not proven exploitable."
    client = _StubClient({"narrative": narrative, "remediation": "Upgrade to 5.4."})
    out = explain_mod.explain_finding(_reachable(), client)
    assert out["provenance"] == "llm"
    assert out["narrative"] == narrative


def test_guard_does_not_apply_to_exploitable_verdict():
    # For an exploitable verdict the narrative is MEANT to assert exploitability;
    # the guard never fires, so the LLM rendering is kept.
    narrative = "This is exploitable via a proven taint path to yaml.load."
    client = _StubClient({"narrative": narrative, "remediation": "Upgrade."})
    out = explain_mod.explain_finding(_exploitable(), client)
    assert out["verdict"] == "exploitable"
    assert out["provenance"] == "llm"
    assert out["narrative"] == narrative


def test_claims_exploitable_flags_affirmative_not_negated():
    claims = explain_mod._claims_exploitable
    # Affirmative, un-negated exploitability assertions -> flagged.
    assert claims("This is exploitable.")
    assert claims("A proven taint path reaches the sink.")
    assert claims("The attacker can reach the vulnerable function.")
    assert claims("A real source -> sink path exists.")
    assert claims("This allows arbitrary code execution.")
    # Broadened guard: more affirmative phrasings are now caught.
    assert claims("This can be exploited by a remote user.")
    assert claims("An attacker could simply exploit this flaw.")
    assert claims("This leads to remote code execution.")
    assert claims("The bug results in arbitrary code execution.")
    assert claims("This gives an attacker RCE on the host.")
    assert claims("The attacker can inject a shell command here.")
    assert claims("The attacker can run arbitrary commands.")
    assert claims("The handler is vulnerable to SSTI and can be abused remotely.")
    # Negated / safe phrasing -> NOT flagged (common reachable-tier wording).
    assert not claims("reachable but not proven exploitable")
    assert not claims("no proven taint path was found")
    assert not claims("the attacker cannot reach the sink")
    assert not claims("the attacker can't reach the sink")
    assert not claims("exploitability is unconfirmed")
    assert not claims("it does not allow arbitrary code execution")
    assert not claims("this cannot be exploited from outside")
    assert not claims("there is no remote code execution risk here")
    assert not claims("")


_BODY_KEYS = {
    "dependency_id",
    "vuln_id",
    "dependency_name",
    "cve_ids",
    "verdict",
    "narrative",
    "remediation",
    "provenance",
    "model",
}


def test_response_body_shape_and_llm_model_label(monkeypatch):
    # When the model actually produced the prose, the branded label is shown.
    monkeypatch.setenv("LLM_MODEL", "llama-4-maverick")
    out = explain_mod.explain_finding(
        _exploitable(), _StubClient({"narrative": "N", "remediation": "R"})
    )
    assert set(out) == _BODY_KEYS
    assert out["cve_ids"] == ["CVE-2020-1747"]
    assert out["provenance"] == "llm"
    assert out["model"] == "Meta Muse (llama-4-maverick)"


def test_offline_path_does_not_show_model_brand(monkeypatch):
    # Honesty (Fix 5): on the offline-heuristic path no model ran, so the
    # ``model`` field must NOT name "Meta Muse" beside an offline analysis.
    monkeypatch.setenv("LLM_MODEL", "llama-4-maverick")
    out = explain_mod.explain_finding(
        _exploitable(), _StubClient(None, available=False)
    )
    assert set(out) == _BODY_KEYS
    assert out["provenance"] == "offline-heuristic"
    assert out["model"] == "offline heuristic"
    assert "Meta Muse" not in out["model"]


def test_model_label_without_env(monkeypatch):
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert explain_mod.model_label() == "Meta Muse"


def test_find_finding_matches_on_both_keys():
    findings = [_exploitable(), _reachable()]
    assert (
        explain_mod.find_finding(findings, "dep:PyPI:PyYAML", "GHSA-reachable")
        is findings[1]
    )
    assert explain_mod.find_finding(findings, "dep:PyPI:PyYAML", "nope") is None
    assert explain_mod.find_finding(findings, "dep:other", "GHSA-reachable") is None


# -- endpoint routing (200 / 404 / 503) ---------------------------------------


def _scan(status: str, findings: list[dict[str, Any]], repo_path: str = ""):
    from scanner.web.app import _ScanState, _repo_name

    repo = _repo_name(repo_path) if repo_path else "acme-api"
    state = _ScanState(repo=repo, repo_path=repo_path)
    if status == "ready":
        state.set_ready(
            findings_total=len(findings),
            exploitable=sum(1 for f in findings if f.get("taint") == "tainted"),
            findings=findings,
        )
    elif status == "degraded":
        state.set_degraded("boom")
    # "scanning" is the default initial state.
    return state


def test_endpoint_returns_explanation_for_match(monkeypatch):
    from scanner.web import app as app_mod

    finding = _exploitable()
    scan = _scan("ready", [finding])
    # No ``repo`` param -> the primary scan (``app.state.scan``).
    app_mod.app.state.scan = scan
    app_mod.app.state.scans = [scan]
    # Force the offline path so no network is touched.
    monkeypatch.setattr(app_mod, "LLMClient", lambda: _StubClient(None, available=False))

    req = app_mod.ExplainRequest(
        dependency_id="dep:PyPI:PyYAML", vuln_id=finding["vuln_id"]
    )
    out = app_mod.explain(req)
    assert out["verdict"] == "exploitable"
    assert out["provenance"] == "offline-heuristic"


def test_endpoint_404_when_absent_in_ready_primary():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    scan = _scan("ready", [_exploitable()])
    app_mod.app.state.scan = scan
    app_mod.app.state.scans = [scan]
    req = app_mod.ExplainRequest(dependency_id="dep:PyPI:PyYAML", vuln_id="missing")
    with pytest.raises(HTTPException) as exc:
        app_mod.explain(req)
    assert exc.value.status_code == 404
    assert exc.value.detail == "finding not in live scan"


def test_endpoint_503_while_primary_still_warming():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    # The primary scan is still warming -> nothing to look the finding up in yet.
    scanning = _scan("scanning", [])
    app_mod.app.state.scan = scanning
    app_mod.app.state.scans = [scanning, _scan("ready", [])]
    req = app_mod.ExplainRequest(dependency_id="dep:PyPI:PyYAML", vuln_id="whatever")
    with pytest.raises(HTTPException) as exc:
        app_mod.explain(req)
    assert exc.value.status_code == 503
    assert exc.value.detail == "scan not ready"


# -- per-repo routing (?repo= selects a warmed scan by repo_path basename) -----


def _secondary_finding() -> dict[str, Any]:
    # Same (dependency_id, vuln_id) as _exploitable(), but a DIFFERENT verdict,
    # so cross-resolution between repos is observable in the response.
    finding = _exploitable()
    finding["taint"] = "not_proven"
    finding["taint_evidence"] = None
    finding["reachable"] = False
    finding["reachable_entrypoints"] = []
    finding["example_path"] = []
    return finding


def test_endpoint_repo_param_uses_matched_scan_not_primary(monkeypatch):
    from scanner.web import app as app_mod

    monkeypatch.setattr(app_mod, "LLMClient", lambda: _StubClient(None, available=False))
    primary = _scan("ready", [_exploitable()], repo_path="/app/samples/acme-api")
    secondary = _scan(
        "ready", [_secondary_finding()], repo_path="/app/samples/plugin-reports"
    )
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary, secondary]

    req = app_mod.ExplainRequest(
        dependency_id="dep:PyPI:PyYAML", vuln_id="GHSA-6757-jp84-gxfx"
    )
    # Same ids resolve to the PRIMARY with no param (exploitable)...
    assert app_mod.explain(req)["verdict"] == "exploitable"
    # ... and to the SECONDARY scan's own finding when ?repo= selects it.
    assert app_mod.explain(req, repo="plugin-reports")["verdict"] == "not_reached"


def test_endpoint_repo_param_unknown_404():
    from fastapi import HTTPException

    from scanner.web import app as app_mod

    primary = _scan("ready", [_exploitable()], repo_path="/app/samples/acme-api")
    app_mod.app.state.scan = primary
    app_mod.app.state.scans = [primary]
    req = app_mod.ExplainRequest(
        dependency_id="dep:PyPI:PyYAML", vuln_id="GHSA-6757-jp84-gxfx"
    )
    with pytest.raises(HTTPException) as exc:
        app_mod.explain(req, repo="does-not-exist")
    assert exc.value.status_code == 404
    assert exc.value.detail == "unknown repo"
