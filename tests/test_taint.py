"""Tests for the sound, inter-procedural taint pass (scanner/taint.py).

Everything here is OFFLINE and deterministic: taint is a pure static analysis
over re-parsed source on proven reachability paths -- no network, no model.

Coverage:
* end-to-end positives on the real fixtures (vulnerable-app, golden-app);
* soundness NEGATIVES built as tiny throwaway repos (no source, ``*args``
  passthrough, the ``requests`` HTTP client is not a source, constant-at-sink);
* unit tests for the taint-preserving propagation ops and arg->param binding;
* a report-level test proving the signal is additive (audit()/build_summary)
  and NEVER changes reachable / verdict / symbol_match / ranking.
"""

from __future__ import annotations

import ast
import os
import textwrap

import pytest

from scanner.correlate import CorrelationResult, Finding
from scanner.correlate import report
from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.analyzers.python_analyzer import _collect, _collect_classes
from scanner.taint import (
    NOT_PROVEN,
    TAINTED,
    TaintResult,
    _ParsedFile,
    _bind_call_args,
    _call_resolves_to,
    _import_aliases,
    _propagate,
    _reconstruct_dotted,
    _source_of,
    _taint_of_expr,
    compute_taint,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_APP = os.path.join(REPO, "samples", "vulnerable-app")
GOLDEN_APP = os.path.join(REPO, "samples", "golden-app")


def _taint_for(path: str):
    graph = scan_repo(path)
    reach = compute_reachability(graph)
    return compute_taint(graph, reach, os.path.abspath(path))


# -- end-to-end positives -----------------------------------------------------


def test_vulnerable_app_pyyaml_is_tainted():
    taint = _taint_for(VULN_APP)
    result = taint["dep:PyPI:PyYAML"]
    assert result.verdict == TAINTED
    assert result.source == "request.get_data"
    assert result.sink_symbol == "yaml.load"
    assert result.entrypoint == "POST /import"
    assert result.path == [
        "ep:POST:/import",
        "fn:app.py:import_data",
        "fn:utils/config_loader.py:load_config",
        "dep:PyPI:PyYAML",
    ]


def test_vulnerable_app_flask_is_not_tainted():
    # Flask is the source library; no attacker value flows INTO a Flask sink.
    taint = _taint_for(VULN_APP)
    assert taint["dep:PyPI:Flask"].verdict == NOT_PROVEN


def test_golden_app_load_route_is_tainted():
    taint = _taint_for(GOLDEN_APP)
    result = taint["dep:PyPI:PyYAML"]
    assert result.verdict == TAINTED
    assert result.source == "request.get_json"
    assert result.sink_symbol == "yaml.safe_load"
    assert result.entrypoint == "POST /load"


def test_golden_app_negatives_stay_not_proven():
    taint = _taint_for(GOLDEN_APP)
    # requests: reached with constant URLs only (the /proxy source is not
    # forwarded); python-dateutil: constant list; Flask: source library.
    assert taint["dep:PyPI:requests"].verdict == NOT_PROVEN
    assert taint["dep:PyPI:python-dateutil"].verdict == NOT_PROVEN
    assert taint["dep:PyPI:Flask"].verdict == NOT_PROVEN


# -- soundness negatives (throwaway repos) ------------------------------------


def _write_repo(tmp_path, files: dict[str, str]):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return str(tmp_path)


_REQS = "Flask==2.0.1\nPyYAML==5.3.1\nrequests==2.25.0\n"


def test_no_source_is_not_proven(tmp_path):
    # A route that reaches the PyYAML sink but with a CONSTANT argument.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    _ = request  # a source object is in scope but never read
                    return yaml.load("a: 1")
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_star_args_passthrough_is_not_proven(tmp_path):
    # Tainted value passed through ``*args`` -> binding declined -> not proven.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    raw = request.get_data()
                    bundle = [raw]
                    return helper(*bundle)

                def helper(data):
                    return yaml.load(data)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_requests_client_is_not_a_source(tmp_path):
    # ``requests.get(...).text`` is an arbitrary call return, never a source.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                import requests
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x")
                def handler():
                    data = requests.get("https://example.com").text
                    return yaml.load(data)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_tmp_repo_positive_sanity(tmp_path):
    # Mirror of the negatives but with a real flow, so the negatives above are
    # proven to be the taint pass refusing -- not the fixture failing to wire.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    raw = request.get_data()
                    return helper(raw)

                def helper(data):
                    return yaml.load(data)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == TAINTED
    assert taint["dep:PyPI:PyYAML"].sink_symbol == "yaml.load"


def test_name_only_binding_does_not_leak_taint(tmp_path):
    # BUG 1 regression: the on-path callee ``services.process`` is reached with a
    # CONSTANT; an UNRELATED same-named ``Harmless.process(evil)`` carries the
    # attacker value. Binding by simple name alone would leak ``evil`` into
    # ``services.process``'s parameter and falsely report PyYAML tainted. The
    # resolver binds only from the call that provably targets ``services.process``
    # (the constant one), so the literal ``"a: 1"`` is what reaches ``yaml.load``.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                from flask import Flask, request
                import services

                app = Flask(__name__)

                class Harmless:
                    def process(self, data):
                        return data

                @app.route("/x", methods=["POST"])
                def handler():
                    evil = request.get_data()
                    h = Harmless()
                    h.process(evil)                 # unrelated, same method name
                    return services.process("a: 1")  # on-path, CONSTANT argument
                """,
            "services.py": """
                import yaml

                def process(raw):
                    return yaml.load(raw)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_straightline_rebind_to_constant_kills_taint(tmp_path):
    # BUG 2 regression: a straight-line reassignment to a constant kills taint;
    # ``x`` is always the constant at the sink, so PyYAML is not proven tainted.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    x = "a: 1"
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_conditional_kill_does_not_suppress_taint(tmp_path):
    # Guards against the flow-sensitivity over-correcting into a FALSE NEGATIVE:
    # a kill inside an ``if`` branch must NOT erase the straight-line binding,
    # because the else-path still reaches the sink with attacker data. The sound
    # existential verdict here is ``tainted`` (some execution reaches the sink
    # tainted). (A stricter sound analysis could report not_proven -- a false
    # negative is acceptable per the cardinal rule -- but this implementation
    # keeps the taint, so we assert ``tainted``.)
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    if request.args.get("c"):
                        x = "const"
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == TAINTED


def test_if_else_both_overwrite_to_constant_is_not_proven(tmp_path):
    # SOUNDNESS: both arms of an if/else overwrite the tainted name to a
    # constant, so the pre-branch taint is ALWAYS killed before the sink. The
    # may-dataflow JOIN kills a name only when EVERY path kills it -> not proven.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    if request.args.get("mode") == "a":
                        x = "a: 1"
                    else:
                        x = "b: 2"
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_with_body_overwrite_to_constant_is_not_proven(tmp_path):
    # SOUNDNESS: a ``with`` body ALWAYS executes, so a straight-line kill inside
    # it genuinely erases the taint before the sink.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    with open("f") as fh:
                        x = "a: 1"
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_match_all_cases_overwrite_to_constant_is_not_proven(tmp_path):
    # SOUNDNESS: every case (including the ``case _`` catch-all) overwrites the
    # tainted name to a constant, so no path reaches the sink tainted.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    match request.args.get("mode"):
                        case "a":
                            x = "a: 1"
                        case "b":
                            x = "b: 2"
                        case _:
                            x = "c: 3"
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == NOT_PROVEN


def test_match_case_keeping_attacker_value_stays_tainted(tmp_path):
    # SOUNDNESS (other direction): one case keeps the attacker value, so some
    # execution reaches the sink tainted -> the join preserves the tainted path.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = request.get_data()
                    match request.args.get("mode"):
                        case "a":
                            x = "a: 1"
                        case _:
                            x = x
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == TAINTED


def test_branch_adds_taint_on_one_path_stays_tainted(tmp_path):
    # SOUNDNESS (other direction): the name starts as a constant and is tainted
    # only inside the ``if`` body; the JOIN keeps the tainted path -> tainted.
    repo = _write_repo(
        tmp_path,
        {
            "requirements.txt": _REQS,
            "app.py": """
                import yaml
                from flask import Flask, request

                app = Flask(__name__)

                @app.route("/x", methods=["POST"])
                def handler():
                    x = "safe"
                    if request.args.get("c"):
                        x = request.get_data()
                    return yaml.load(x)
                """,
        },
    )
    taint = _taint_for(repo)
    assert taint["dep:PyPI:PyYAML"].verdict == TAINTED


# -- unit tests: call-site resolver (method vs. module, same name) ------------


def _parsed_module(src: str):
    """Parse a module -> ``(tree, _ParsedFile)`` mirroring the pass's cache."""
    tree = ast.parse(textwrap.dedent(src))
    functions, _ = _collect(tree)
    _, method_meta = _collect_classes(tree)
    parsed = _ParsedFile(
        defs={qual: node for qual, node in functions},
        method_meta=method_meta,
        import_aliases=_import_aliases(tree),
    )
    return tree, parsed


def _attr_call(fnode, recv_id):
    return next(
        c
        for c in ast.walk(fnode)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and isinstance(c.func.value, ast.Name)
        and c.func.value.id == recv_id
    )


def test_resolver_self_method_binds_not_unrelated_receiver():
    # Method callee ``C.process``: ``self.process(...)`` inside a method of C
    # resolves; an unrelated ``helper.process(...)`` with an unknown receiver
    # class does not.
    _, parsed = _parsed_module(
        """
        class C:
            def handle(self, x):
                self.process(x)
                helper.process(x)
            def process(self, x):
                return x
        """
    )
    handle = parsed.defs["C.handle"]
    self_call = _attr_call(handle, "self")
    other_call = _attr_call(handle, "helper")
    assert _call_resolves_to(
        self_call, "m.py", "C.handle", parsed, handle, "m.py", "C.process", True
    ) is True
    assert _call_resolves_to(
        other_call, "m.py", "C.handle", parsed, handle, "m.py", "C.process", True
    ) is False


def test_resolver_module_func_not_matched_by_method_call():
    # Module-level callee ``services.process``: ``services.process(...)`` (alias
    # resolves to the callee's module) binds; an unrelated ``obj.process(...)``
    # (receiver not an import of that module) does not.
    _, parsed = _parsed_module(
        """
        import services

        def h():
            services.process("a: 1")
            obj.process(evil)
        """
    )
    h = parsed.defs["h"]
    svc_call = _attr_call(h, "services")
    obj_call = _attr_call(h, "obj")
    assert _call_resolves_to(
        svc_call, "app.py", "h", parsed, h, "services.py", "process", False
    ) is True
    assert _call_resolves_to(
        obj_call, "app.py", "h", parsed, h, "services.py", "process", False
    ) is False


# -- unit tests: source recognition -------------------------------------------


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


@pytest.mark.parametrize(
    "src,expected",
    [
        ("request.args", "request.args"),
        ("request.form", "request.form"),
        ("request.json", "request.json"),
        ("request.get_json()", "request.get_json"),
        ("request.get_data(as_text=True)", "request.get_data"),
        ("request.args.get('q')", "request.args"),
        ("request.headers.get('X')", "request.headers"),
    ],
)
def test_source_recognised(src, expected):
    assert _source_of(_expr(src)) == expected


@pytest.mark.parametrize(
    "src",
    [
        "requests.get('u')",  # HTTP client, not the request object
        "requests.args",
        "other.args",
        "helper(x)",
        "'constant'",
    ],
)
def test_non_source_not_recognised(src):
    assert _source_of(_expr(src)) is None


# -- unit tests: taint-preserving ops -----------------------------------------


def test_taint_preserving_ops():
    env = {"x": {"src"}}
    assert _taint_of_expr(_expr("x"), env) == {"src"}
    assert _taint_of_expr(_expr("x + '!'"), env) == {"src"}  # concat / BinOp
    assert _taint_of_expr(_expr("f'val={x}'"), env) == {"src"}  # f-string
    assert _taint_of_expr(_expr("x[0]"), env) == {"src"}  # subscript
    assert _taint_of_expr(_expr("x.attr"), env) == {"src"}  # attribute
    assert _taint_of_expr(_expr("'t={}'.format(x)"), env) == {"src"}  # .format
    assert _taint_of_expr(_expr("[x, 1]"), env) == {"src"}  # container literal
    assert _taint_of_expr(_expr("x if c else 'd'"), env) == {"src"}  # IfExp


def test_arbitrary_call_return_is_not_tainted():
    env = {"x": {"src"}}
    # A return value of an arbitrary call is never tainted (conservative).
    assert _taint_of_expr(_expr("sanitize(x)"), env) == set()
    assert _taint_of_expr(_expr("obj.method(x)"), env) == set()


def test_constant_named_like_a_source_is_not_tainted():
    env: dict = {}
    assert _taint_of_expr(_expr("'mode: ro'"), env) == set()


# -- unit tests: intra-procedural propagation ---------------------------------


def _fn(src: str) -> ast.AST:
    return ast.parse(textwrap.dedent(src)).body[0]


def test_propagate_alias_and_for_and_with():
    fn = _fn(
        """
        def f():
            y = x            # alias from a seeded-tainted name
            for item in y:   # for over tainted iterable
                z = item
            return z
        """
    )
    env = _propagate(fn, {"x": {"src"}})
    assert env.get("y") == {"src"}
    assert env.get("item") == {"src"}
    assert env.get("z") == {"src"}


def test_propagate_does_not_taint_from_call_return():
    fn = _fn(
        """
        def f():
            y = clean(x)
            return y
        """
    )
    env = _propagate(fn, {"x": {"src"}})
    assert "y" not in env


# -- unit tests: argument -> parameter binding --------------------------------


def _call(src: str) -> ast.Call:
    return ast.parse(src, mode="eval").body


def test_bind_positional_argument():
    nxt = _fn("def g(a, b):\n    pass")
    seed: dict = {}
    _bind_call_args(_call("g(x, 'c')"), nxt, False, {"x": {"s"}}, seed)
    assert seed == {"a": {"s"}}


def test_bind_keyword_argument():
    nxt = _fn("def g(a, b):\n    pass")
    seed: dict = {}
    _bind_call_args(_call("g(1, b=x)"), nxt, False, {"x": {"s"}}, seed)
    assert seed == {"b": {"s"}}


def test_bind_skips_self_for_method():
    # ``obj.m(x)`` binds x to the FIRST non-self param of ``def m(self, a)``.
    nxt = _fn("def m(self, a):\n    pass")
    seed: dict = {}
    _bind_call_args(_call("obj.m(x)"), nxt, True, {"x": {"s"}}, seed)
    assert seed == {"a": {"s"}}


def test_bind_declined_for_star_args():
    nxt = _fn("def g(a):\n    pass")
    seed: dict = {}
    _bind_call_args(_call("g(*rest)"), nxt, False, {"rest": {"s"}}, seed)
    assert seed == {}


def test_bind_declined_when_too_many_positional_args():
    nxt = _fn("def g(a):\n    pass")
    seed: dict = {}
    _bind_call_args(_call("g(x, y)"), nxt, False, {"x": {"s"}, "y": {"s"}}, seed)
    assert seed == {}


# -- unit tests: sink reconstruction respects shadowing -----------------------


def test_reconstruct_respects_import_alias():
    call = _call("y.load(raw)")
    dotted = _reconstruct_dotted(call.func, set(), {}, {"y": "yaml"})
    assert dotted == "yaml.load"


def test_reconstruct_declines_shadowed_root():
    # ``yaml`` is locally bound (a parameter) -> not the package import.
    call = _call("yaml.load(raw)")
    dotted = _reconstruct_dotted(call.func, {"yaml"}, {}, {"yaml": "yaml"})
    assert dotted is None


# -- report-level: additive, never changes the pre-existing signals -----------


def _findings() -> list[Finding]:
    """Fresh findings for PyYAML (reached) and Flask (reached) on vulnerable-app."""
    return [
        Finding(
            dependency_id="dep:PyPI:PyYAML",
            dependency_name="PyYAML",
            version="5.3.1",
            ecosystem="PyPI",
            vuln_id="GHSA-pyyaml-x",
            cve_ids=["CVE-2020-1747"],
            summary="PyYAML arbitrary code execution via yaml.load",
            fixed_versions=["5.3.1"],
            details="The yaml.load function is the vulnerable sink.",
            epss=0.5,
        ),
        Finding(
            dependency_id="dep:PyPI:Flask",
            dependency_name="Flask",
            version="2.0.1",
            ecosystem="PyPI",
            vuln_id="GHSA-flask-y",
            cve_ids=["CVE-2000-0000"],
            summary="Flask issue",
            fixed_versions=[],
            epss=0.9,
        ),
    ]


def _signals(payload: dict) -> list[tuple]:
    return [
        (f["dependency_id"], f["reachable"], f["verdict"], f["symbol_match"])
        for f in payload["findings"]
    ]


def test_audit_taint_is_additive_and_sets_summary():
    graph = scan_repo(VULN_APP)
    reach = compute_reachability(graph)
    taint_map = compute_taint(graph, reach, VULN_APP)

    baseline = report.audit(
        graph,
        CorrelationResult(findings=_findings(), offline=True, network_ok=False),
        reach,
    )
    with_taint = report.audit(
        graph,
        CorrelationResult(findings=_findings(), offline=True, network_ok=False),
        reach,
        taint=taint_map,
    )

    # Ranking order, reachable, verdict and symbol_match are byte-for-byte equal.
    assert _signals(baseline) == _signals(with_taint)

    # The taint signal appears only when the map is passed.
    by_id = {f["dependency_id"]: f for f in with_taint["findings"]}
    assert by_id["dep:PyPI:PyYAML"]["taint"] == "tainted"
    assert by_id["dep:PyPI:PyYAML"]["taint_evidence"]["sink_symbol"] == "yaml.load"
    assert by_id["dep:PyPI:Flask"]["taint"] == "not_proven"

    # Baseline leaves every taint field at the conservative default.
    assert all(f["taint"] == "not_proven" for f in baseline["findings"])

    # The new summary counter is present in both and counts only tainted deps.
    assert baseline["summary"]["taint_confirmed_vulnerabilities"] == 0
    assert with_taint["summary"]["taint_confirmed_vulnerabilities"] == 1
    # No other summary counter moved.
    for key in baseline["summary"]:
        if key != "taint_confirmed_vulnerabilities":
            assert baseline["summary"][key] == with_taint["summary"][key]


def _pyyaml_finding(vuln_id: str, summary: str, details: str | None = None) -> Finding:
    return Finding(
        dependency_id="dep:PyPI:PyYAML",
        dependency_name="PyYAML",
        version="5.3.1",
        ecosystem="PyPI",
        vuln_id=vuln_id,
        cve_ids=[],
        summary=summary,
        fixed_versions=[],
        details=details,
    )


def test_taint_is_gated_per_finding_by_advisory_sink():
    """Two CVEs on the SAME tainted dependency: only the one naming the tainted
    sink (yaml.load) is tainted; the one about another function is not_proven."""
    graph = scan_repo(VULN_APP)
    reach = compute_reachability(graph)
    taint_map = compute_taint(graph, reach, VULN_APP)
    assert taint_map["dep:PyPI:PyYAML"].sink_symbol == "yaml.load"

    findings = [
        _pyyaml_finding("GHSA-sink", "PyYAML arbitrary code execution via yaml.load"),
        _pyyaml_finding(
            "GHSA-other",
            "PyYAML denial of service in the emitter",
            "Crafted input to yaml.dump can exhaust memory.",
        ),
        _pyyaml_finding("GHSA-vague", "PyYAML vulnerability"),
    ]
    payload = report.audit(
        graph,
        CorrelationResult(findings=findings, offline=True, network_ok=False),
        reach,
        taint=taint_map,
    )
    by_id = {f["vuln_id"]: f for f in payload["findings"]}

    assert by_id["GHSA-sink"]["taint"] == "tainted"
    assert by_id["GHSA-sink"]["taint_evidence"]["sink_symbol"] == "yaml.load"
    for vuln_id in ("GHSA-other", "GHSA-vague"):
        assert by_id[vuln_id]["taint"] == "not_proven"
        assert by_id[vuln_id]["taint_evidence"] is None
    assert payload["summary"]["taint_confirmed_vulnerabilities"] == 1

    # Nesting invariant: tainted implies a confirmed symbol match.
    for f in payload["findings"]:
        if f["taint"] == "tainted":
            assert f["symbol_match"] == "confirmed"


def test_tainted_never_without_sink_symbol_or_tainted_verdict():
    findings = [_pyyaml_finding("GHSA-sink", "PyYAML code execution via yaml.load")]
    for result in (
        TaintResult(verdict=TAINTED, sink_symbol=None),
        TaintResult(verdict=TAINTED, sink_symbol=""),
        TaintResult(verdict=NOT_PROVEN, sink_symbol="yaml.load"),
    ):
        report._apply_taint(findings, {"dep:PyPI:PyYAML": result})
        assert findings[0].taint == "not_proven"
        assert findings[0].taint_evidence is None


def test_vulnerable_app_taint_implies_confirmed_symbol_match():
    graph = scan_repo(VULN_APP)
    reach = compute_reachability(graph)
    taint_map = compute_taint(graph, reach, VULN_APP)
    payload = report.audit(
        graph,
        CorrelationResult(findings=_findings(), offline=True, network_ok=False),
        reach,
        taint=taint_map,
    )
    tainted = [f for f in payload["findings"] if f["taint"] == "tainted"]
    assert tainted  # the PyYAML finding's advisory names yaml.load
    assert all(f["symbol_match"] == "confirmed" for f in tainted)


def test_taint_result_to_dict_roundtrips():
    r = TaintResult(verdict=TAINTED, source="request.data", sink_symbol="yaml.load",
                    entrypoint="POST /x", path=["a", "b"])
    assert r.to_dict() == {
        "verdict": "tainted",
        "source": "request.data",
        "sink_symbol": "yaml.load",
        "entrypoint": "POST /x",
        "path": ["a", "b"],
    }
