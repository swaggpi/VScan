"""Dynamic-usage investigation tests -- MUST NOT touch the network.

The dynamic-usage tier investigates VULNERABLE dependencies that have NO
statically resolved call edge -- the deps triage cannot cover. These tests use
small, hand-built knowledge graphs plus tiny synthetic repositories written into
``tmp_path`` (so the deterministic evidence pass has real files to walk), and
the LLM client is either forced offline or replaced with a canned stub, so no
request is ever issued. They exercise:

* target-set selection: a vulnerable dep with NO ``calls`` edge is a target, a
  dep WITH a call edge is excluded (triage covers it), and a dep with no finding
  is never a target;
* the offline classification for each usage_kind from synthetic evidence
  (config_or_infra, dynamic_import, dev_or_build_only, uncertain, not_found);
* the PyPI import-name alias (``PyYAML`` -> ``yaml``) and the evidence cap;
* the no-fabrication / advisory guardrails: every record is advisory, the pass
  mutates neither the graph nor any finding, and a model can only return an
  in-vocabulary usage_kind (out-of-vocab -> uncertain);
* the ``report.audit`` None-compatibility (payload unchanged when usage is not
  passed) and serialization under the ``"usage"`` key when provided;
* the CLI wiring (``--bundle`` / ``--json`` gain a ``usage`` key, default text
  output has none, ``--explain`` prints the section).
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

from scanner.agent import LLMClient, Usage, investigate_usage
from scanner.agent.usage import _build_targets
from scanner.cli import main
from scanner.correlate import Finding, correlate_full, enrich, osv
from scanner.correlate import report
from scanner.graph import KnowledgeGraph
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)
DEMO_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "demo-app",
)


# -- fixtures / helpers -------------------------------------------------------


def _graph(*deps: tuple[str, str, str]) -> KnowledgeGraph:
    """A minimal graph with the given ``(id, name, ecosystem)`` dependencies."""
    g = KnowledgeGraph()
    for dep_id, name, eco in deps:
        g.add_node(dep_id, "dependency", name, version="1.0", ecosystem=eco)
    return g


def _finding(dep_id: str, name: str, *, eco: str = "PyPI", cve: str = "CVE-0000-1") -> Finding:
    return Finding(
        dependency_id=dep_id,
        dependency_name=name,
        version="1.0",
        ecosystem=eco,
        vuln_id="GHSA-xxxx",
        cve_ids=[cve],
        summary=f"{name} has a vulnerability.",
        fixed_versions=[],
        severity="HIGH",
    )


def _write(root, relpath: str, content: str) -> None:
    path = os.path.join(str(root), relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _run(repo, graph, findings) -> list[Usage]:
    reach = compute_reachability(graph)
    return investigate_usage(str(repo), graph, findings, reach, client=LLMClient.disabled())


class _StubClient:
    """A canned OpenAI-compatible client stub (duck-typed for investigate_usage)."""

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


# -- target selection ---------------------------------------------------------


def test_target_excludes_called_deps_and_findingless_deps():
    g = _graph(
        ("dep:PyPI:called", "called", "PyPI"),
        ("dep:PyPI:uncalled", "uncalled", "PyPI"),
        ("dep:PyPI:nofinding", "nofinding", "PyPI"),
    )
    # A resolved static call into "called" -> triage's job, not this tier.
    g.add_edge("fn:app.py:main", "dep:PyPI:called", "calls", symbol="called.run")
    findings = [_finding("dep:PyPI:called", "called"), _finding("dep:PyPI:uncalled", "uncalled")]
    targets = _build_targets(g, findings)
    assert [t.dependency_id for t in targets] == ["dep:PyPI:uncalled"]


def test_empty_when_no_findings(tmp_path):
    g = _graph(("dep:PyPI:x", "x", "PyPI"))
    assert _run(tmp_path, g, []) == []


# -- offline classification: one per usage_kind -------------------------------


def test_offline_config_or_infra(tmp_path):
    _write(tmp_path, "Procfile", "web: gunicorn app:app --workers 4\n")
    g = _graph(("dep:PyPI:gunicorn", "gunicorn", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:gunicorn", "gunicorn")])[0]
    assert u.usage_kind == "config_or_infra"
    assert u.confidence == "medium"
    assert any(e["source"] == "Procfile" for e in u.evidence)
    assert "config" in u.summary.lower() or "infrastructure" in u.summary.lower()


def test_offline_dynamic_import(tmp_path):
    _write(tmp_path, "plugins.py", 'import importlib\nmod = importlib.import_module("plugsample")\n')
    g = _graph(("dep:PyPI:plugsample", "plugsample", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:plugsample", "plugsample")])[0]
    assert u.usage_kind == "dynamic_import"
    assert u.confidence == "medium"
    assert any(e["source"] == "plugins.py" for e in u.evidence)


def test_offline_dev_or_build_only(tmp_path):
    _write(tmp_path, "tests/test_thing.py", "import devonlydep\n\ndef test_x():\n    assert devonlydep\n")
    g = _graph(("dep:PyPI:devonlydep", "devonlydep", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:devonlydep", "devonlydep")])[0]
    assert u.usage_kind == "dev_or_build_only"
    assert u.confidence == "low"
    assert all("test" in e["source"] for e in u.evidence)


def test_offline_uncertain_for_general_source(tmp_path):
    _write(tmp_path, "src/app.py", "import plaindep\n\nplaindep.do()\n")
    g = _graph(("dep:PyPI:plaindep", "plaindep", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:plaindep", "plaindep")])[0]
    assert u.usage_kind == "uncertain"
    assert u.evidence  # the reference was found and cited...
    assert "could not be determined" in u.summary  # ...but how it is loaded is unclear


def test_offline_not_found_is_honest_about_transitive(tmp_path):
    _write(tmp_path, "src/app.py", "print('hello')\n")
    g = _graph(("dep:PyPI:ghostdep", "ghostdep", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:ghostdep", "ghostdep")])[0]
    assert u.usage_kind == "not_found"
    assert u.confidence == "low"
    assert u.evidence == []
    assert "transitive" in u.summary.lower()
    # Never CLAIMS the dependency is unused/safe -- it explicitly denies that
    # absence of a reference means unused or safe.
    assert "not evidence that it is unused or safe" in u.summary.lower()


# -- import-name alias + evidence cap -----------------------------------------


def test_pypi_import_name_alias_is_searched(tmp_path):
    g = _graph(("dep:PyPI:PyYAML", "PyYAML", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:PyYAML", "PyYAML")])[0]
    assert "yaml" in u.import_names  # the well-known import-name alias
    assert "pyyaml" in u.import_names


def test_evidence_is_capped(tmp_path):
    lines = "".join(f"capdep usage on line {i}\n" for i in range(40))
    _write(tmp_path, "notes.md", lines)
    g = _graph(("dep:PyPI:capdep", "capdep", "PyPI"))
    u = _run(tmp_path, g, [_finding("dep:PyPI:capdep", "capdep")])[0]
    assert len(u.evidence) <= 12
    assert all(len(e["snippet"]) <= 200 for e in u.evidence)


# -- LLM path (mocked) + conservative normalization ---------------------------


def test_llm_path_produces_record_and_sees_evidence(tmp_path):
    _write(tmp_path, "Procfile", "web: gunicorn app:app\n")
    g = _graph(("dep:PyPI:gunicorn", "gunicorn", "PyPI"))
    client = _StubClient(
        {"usage_kind": "config_or_infra", "summary": "Launched by the Procfile.", "confidence": "high"}
    )
    reach = compute_reachability(g)
    u = investigate_usage(str(tmp_path), g, [_finding("dep:PyPI:gunicorn", "gunicorn")], reach, client=client)[0]
    assert u.provenance == "llm"
    assert u.usage_kind == "config_or_infra"
    assert u.confidence == "high"
    assert u.summary == "Launched by the Procfile."
    # The deterministic evidence is handed to the model.
    assert "gunicorn" in client.last_user_prompt
    assert "Procfile" in client.last_user_prompt


def test_out_of_vocab_model_kind_collapses_to_uncertain(tmp_path):
    _write(tmp_path, "src/app.py", "import plaindep\n")
    g = _graph(("dep:PyPI:plaindep", "plaindep", "PyPI"))
    client = _StubClient({"usage_kind": "definitely_safe", "summary": "s", "confidence": "super"})
    reach = compute_reachability(g)
    u = investigate_usage(str(tmp_path), g, [_finding("dep:PyPI:plaindep", "plaindep")], reach, client=client)[0]
    assert u.usage_kind == "uncertain"
    assert u.confidence == "low"  # out-of-vocab confidence -> conservative default


def test_llm_error_falls_back_to_offline(tmp_path):
    _write(tmp_path, "Procfile", "web: gunicorn app:app\n")
    g = _graph(("dep:PyPI:gunicorn", "gunicorn", "PyPI"))
    client = _StubClient(None)  # any client error -> None -> offline fallback
    reach = compute_reachability(g)
    u = investigate_usage(str(tmp_path), g, [_finding("dep:PyPI:gunicorn", "gunicorn")], reach, client=client)[0]
    assert u.provenance == "offline-heuristic"
    assert u.usage_kind == "config_or_infra"


# -- hard guardrail -----------------------------------------------------------


def test_guardrail_pass_mutates_nothing(tmp_path):
    _write(tmp_path, "Procfile", "web: gunicorn app:app\n")
    _write(tmp_path, "src/app.py", "import plaindep\n")
    g = _graph(
        ("dep:PyPI:gunicorn", "gunicorn", "PyPI"),
        ("dep:PyPI:plaindep", "plaindep", "PyPI"),
        ("dep:PyPI:called", "called", "PyPI"),
    )
    g.add_edge("fn:app.py:main", "dep:PyPI:called", "calls", symbol="called.run")
    findings = [
        _finding("dep:PyPI:gunicorn", "gunicorn"),
        _finding("dep:PyPI:plaindep", "plaindep"),
        _finding("dep:PyPI:called", "called"),
    ]

    graph_before = g.to_dict()
    reachable_before = [f.reachable for f in findings]

    result = _run(tmp_path, g, findings)

    assert g.to_dict() == graph_before
    assert [f.reachable for f in findings] == reachable_before == [False, False, False]
    # "called" (has a call edge) is excluded; the other two are investigated.
    assert {u.dependency_id for u in result} == {"dep:PyPI:gunicorn", "dep:PyPI:plaindep"}
    for u in result:
        assert isinstance(u, Usage)
        assert u.advisory is True
        assert u.provenance in {"llm", "offline-heuristic"}
        assert u.usage_kind in {
            "dynamic_import", "config_or_infra", "transitive_or_indirect",
            "dev_or_build_only", "not_found", "uncertain",
        }
        assert u.confidence in {"low", "medium", "high"}
        assert u.key == u.dependency_id
        assert "does not" in u.note.lower()
        assert "unused" in u.note.lower()  # the guardrail restates the rule


# -- report.audit None-compatibility + serialization --------------------------


@pytest.fixture(scope="module")
def graph():
    return scan_repo(SAMPLE_APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


def test_audit_payload_byte_compatible_when_usage_absent(graph, reach):
    correlation = correlate_full(graph, offline=True)
    without = report.audit(graph, correlation, reach)
    none_arg = report.audit(graph, correlation, reach, usage=None)
    assert "usage" not in without
    assert without == none_arg


def test_audit_payload_serializes_usage_when_provided(graph, reach):
    correlation = correlate_full(graph, offline=True)
    u = Usage(
        dependency_id="dep:PyPI:gunicorn",
        dependency_name="gunicorn",
        version="1.0",
        cves=["CVE-0000-1"],
        import_names=["gunicorn"],
        evidence=[{"source": "Procfile", "line": 1, "snippet": "web: gunicorn app:app"}],
        usage_kind="config_or_infra",
        summary="Launched by the Procfile.",
        confidence="medium",
        provenance="offline-heuristic",
        key="dep:PyPI:gunicorn",
    )
    payload = report.audit(graph, correlation, reach, usage=[u])
    assert isinstance(payload["usage"], list) and len(payload["usage"]) == 1
    serialized = payload["usage"][0]
    assert serialized["key"] == "dep:PyPI:gunicorn"
    assert serialized["usage_kind"] == "config_or_infra"
    assert serialized["advisory"] is True


# -- CLI wiring ---------------------------------------------------------------


# Recorded OSV + enrichment fixtures so ``audit`` finds a real vulnerable dep
# with NO resolved static call edge -- the dynamic-usage tier's exact target.
# urllib3 is declared in vulnerable-app but never called, so marking it
# vulnerable makes the usage tier emit exactly one record. This lets the
# CLI-wiring tests assert the tier is actually POPULATED; an empty list would
# mean the CLI stopped invoking it, which an ``isinstance(list)``-only check
# cannot catch. ``--offline`` cannot be used (it zeroes the vuln findings, so
# usage would be legitimately empty), so we patch every network boundary (OSV,
# KEV, EPSS) and force the LLM client unavailable -- the usage tier runs its
# deterministic offline heuristic and no request is ever issued, honouring this
# module's no-network contract.
_URLLIB3_CVE = "CVE-2021-33503"
_OSV_RECORDS = {
    "GHSA-urllib3-redos": {
        "id": "GHSA-urllib3-redos",
        "summary": "urllib3 catastrophic backtracking (ReDoS) in authority parsing",
        "details": "A crafted URL can cause catastrophic backtracking.",
        "aliases": [_URLLIB3_CVE],
        "database_specific": {"severity": "HIGH"},
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            }
        ],
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "99.0"}],
                    }
                ],
            }
        ],
    },
}
_OSV_IDS_BY_NAME = {"urllib3": ["GHSA-urllib3-redos"]}


@pytest.fixture
def mocked_vuln_db(tmp_path, monkeypatch):
    """Patch every network boundary so ``audit`` finds the urllib3 CVE offline.

    Mirrors ``tests/test_correlate.py``'s ``mocked_db``: OSV / KEV / EPSS return
    recorded fixtures, the on-disk cache is redirected to a temp dir, and the LLM
    client is forced unavailable so the usage tier uses its deterministic offline
    heuristic. No request is ever issued.
    """
    monkeypatch.setenv("VSCAN_CACHE_DIR", str(tmp_path / "vscan-cache"))
    monkeypatch.setattr(
        osv,
        "query_batch",
        lambda queries: [
            _OSV_IDS_BY_NAME.get(q["package"]["name"], []) for q in queries
        ],
    )
    monkeypatch.setattr(osv, "fetch_vuln", lambda vuln_id: _OSV_RECORDS[vuln_id])
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: set())
    monkeypatch.setattr(enrich, "query_epss", lambda cves: {_URLLIB3_CVE: (0.2, 0.5)})
    monkeypatch.setattr(LLMClient, "available", lambda self: False)


def test_cli_bundle_includes_usage_key(tmp_path, mocked_vuln_db):
    # `audit --bundle` carries the advisory dynamic-usage tier, POPULATED:
    # urllib3 is vulnerable with NO resolved call edge in vulnerable-app, so it
    # is a usage target and the tier must emit a non-empty list.
    bundle_path = tmp_path / "bundle.json"
    rc = main(["audit", SAMPLE_APP, "--bundle", str(bundle_path)])
    assert rc == 0
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert "usage" in bundle
    usage = bundle["usage"]
    assert isinstance(usage, list) and usage, "usage tier must be wired + non-empty"
    entry = usage[0]
    assert entry["dependency_id"]
    assert entry["key"] == entry["dependency_id"]  # usage keys on the dep id


def test_cli_audit_json_gains_usage_key(tmp_path, mocked_vuln_db):
    out_path = tmp_path / "audit.json"
    rc = main(["audit", SAMPLE_APP, "--json", "-o", str(out_path)])
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "usage" in payload
    usage = payload["usage"]
    assert isinstance(usage, list) and usage, "usage tier must be wired + non-empty"
    entry = usage[0]
    assert entry["dependency_id"]
    assert entry["key"] == entry["dependency_id"]  # usage keys on the dep id


def test_cli_default_text_output_has_no_usage_section(capsys):
    rc = main(["audit", DEMO_APP, "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dynamic-usage investigation" not in out


def test_cli_explain_prints_usage_section(capsys):
    rc = main(["audit", DEMO_APP, "--offline", "--explain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dynamic-usage investigation (advisory tier)" in out
