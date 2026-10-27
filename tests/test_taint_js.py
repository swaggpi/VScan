"""Tests for the JavaScript adapter of the sound taint pass.

Everything here is OFFLINE and deterministic: taint is a pure static analysis
over re-parsed source on proven reachability paths -- no network, no model, no
``npm install`` (the dependency node, the ``calls`` edge and the resolved symbol
all come from the analyzer offline).

Coverage:
* end-to-end positive on the real fixture (``samples/js-taint-app``: the
  cross-file ``req.body -> lodash.merge`` flow), and its js-yaml negative;
* soundness NEGATIVES as tiny throwaway repos (no sink, rebind-to-constant,
  constant-only sink, call-return laundering, spread args, name-only binding,
  both-branch kill);
* soundness POSITIVES confirming the pass still keeps a real flow (single-branch
  kill, body/param destructuring of the request);
* a guard that the Python suite is unaffected (the JS adapter only activates on
  ``.js`` files).
"""

from __future__ import annotations

import os
import textwrap

from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.taint import NOT_PROVEN, TAINTED, compute_taint

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_TAINT_APP = os.path.join(REPO, "samples", "js-taint-app")

# A manifest declaring the two packages the throwaway handlers reach, so the
# analyzer emits ``dep:npm:*`` nodes (and therefore resolves the sink symbols).
_PKG = (
    '{\n'
    '  "name": "t",\n'
    '  "version": "1.0.0",\n'
    '  "dependencies": {\n'
    '    "express": "^4.18.2",\n'
    '    "lodash": "4.17.21"\n'
    '  }\n'
    '}\n'
)

# A ``sink`` helper whose lodash.merge call is the dependency sink, plus the
# Express wiring. ``{body}`` is substituted with each test's handler body.
_SERVER_TEMPLATE = """\
'use strict';
const express = require('express');
const _ = require('lodash');
const app = express();

function sink(cfg) {{
  return _.merge({{}}, cfg);
}}

{handler}

app.post('/x', handler);
module.exports = {{ app }};
"""


def _taint_for(path: str):
    graph = scan_repo(path)
    reach = compute_reachability(graph)
    return compute_taint(graph, reach, os.path.abspath(path))


def _write_repo(tmp_path, files: dict[str, str]) -> str:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return str(tmp_path)


def _lodash_verdict_for_handler(tmp_path, handler: str) -> str:
    """Build a one-file repo whose handler body feeds ``sink`` and run taint."""
    repo = _write_repo(
        tmp_path,
        {
            "package.json": _PKG,
            "server.js": _SERVER_TEMPLATE.format(handler=textwrap.dedent(handler)),
        },
    )
    return _taint_for(repo)["dep:npm:lodash"].verdict


# -- end-to-end on the real fixture -------------------------------------------


def test_js_taint_app_lodash_is_tainted():
    taint = _taint_for(JS_TAINT_APP)
    result = taint["dep:npm:lodash"]
    assert result.verdict == TAINTED
    assert result.source == "req.body"
    assert result.sink_symbol == "lodash.merge"
    assert result.entrypoint == "POST /merge"
    assert result.path == [
        "ep:POST:/merge",
        "fn:server.js:handleMerge",
        "fn:settings.js:applyDefaults",
        "dep:npm:lodash",
    ]


def test_js_taint_app_jsyaml_is_not_tainted():
    # js-yaml is reached only by the rebind-to-constant and constant-only
    # routes, neither of which proves a flow.
    taint = _taint_for(JS_TAINT_APP)
    assert taint["dep:npm:js-yaml"].verdict == NOT_PROVEN


# -- soundness negatives (throwaway repos) ------------------------------------


def test_no_sink_route_is_not_proven(tmp_path):
    # Reads a request source but never passes it to the dependency call.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          const q = req.query.term;
          res.json({ echo: q });
          sink({ mode: 'ro' });
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_rebind_to_constant_is_not_proven(tmp_path):
    # Straight-line reassignment to a constant KILLS taint before the sink.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          let cfg = req.body;
          cfg = { mode: 'ro' };
          sink(cfg);
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_constant_only_sink_is_not_proven(tmp_path):
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          sink({ mode: 'ro' });
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_call_return_laundering_is_not_proven(tmp_path):
    # An arbitrary call's return value is never tainted (JSON.parse here), so the
    # value that reaches the sink is not proven tainted.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          const parsed = JSON.parse(req.body);
          sink(parsed);
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_spread_args_are_not_bound(tmp_path):
    # A spread argument declines the arg->param binding (conservative).
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          const parts = [req.body];
          sink(...parts);
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_if_else_both_overwrite_to_constant_is_not_proven(tmp_path):
    # Both arms kill the tainted name -> the may-JOIN removes it (every path
    # kills) -> not proven.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          let cfg = req.body;
          if (req.query.flag) {
            cfg = { a: 1 };
          } else {
            cfg = { b: 2 };
          }
          sink(cfg);
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_name_only_binding_does_not_leak_taint(tmp_path):
    # The on-path sink caller is the CROSS-FILE export ``helper.run``; a decoy
    # local ``run`` with the SAME simple name carries the attacker value. Binding
    # by bare name would leak ``req.body`` into ``helper.run``'s parameter. The
    # adapter binds only from the call the analyzer resolves to the on-path fn id
    # (the cross-file ``helper.run('safe')`` with a CONSTANT), so no leak.
    repo = _write_repo(
        tmp_path,
        {
            "package.json": _PKG,
            "server.js": """
                'use strict';
                const express = require('express');
                const helper = require('./helper');
                const app = express();

                // Decoy: a local fn sharing the export's simple name, fed evil.
                function run(data) {
                  return data;
                }

                function handler(req, res) {
                  run(req.body);               // resolves to LOCAL run -> off path
                  helper.run('safe: 1');        // on-path sink caller, CONSTANT
                }

                app.post('/x', handler);
                module.exports = { app };
                """,
            "helper.js": """
                'use strict';
                const _ = require('lodash');
                function run(cfg) {
                  return _.merge({}, cfg);
                }
                module.exports = { run };
                """,
        },
    )
    assert _taint_for(repo)["dep:npm:lodash"].verdict == NOT_PROVEN


# -- soundness positives (a real flow must still be kept) ---------------------


def test_positive_sanity_direct_flow_is_tainted(tmp_path):
    # Mirror of the negatives but with a real flow, proving they are the pass
    # refusing -- not the wiring failing.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          sink(req.body);
        }
        """,
    )
    assert verdict == TAINTED


def test_single_branch_kill_stays_tainted(tmp_path):
    # Only one arm kills; the implicit-else path keeps the attacker value, so
    # some execution reaches the sink tainted -> the JOIN preserves it.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          let cfg = req.body;
          if (req.query.flag) {
            cfg = { a: 1 };
          }
          sink(cfg);
        }
        """,
    )
    assert verdict == TAINTED


def test_body_destructuring_source_is_tainted(tmp_path):
    # ``const {body} = req`` destructures the request object into a source name.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          const { body } = req;
          sink(body);
        }
        """,
    )
    assert verdict == TAINTED


def test_param_destructuring_source_is_tainted(tmp_path):
    # Param destructuring ``function handler({ body }, res)`` taints ``body``.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler({ body }, res) {
          sink(body);
        }
        """,
    )
    assert verdict == TAINTED


def test_template_literal_flow_is_tainted(tmp_path):
    # A template literal embedding the source is taint-preserving.
    verdict = _lodash_verdict_for_handler(
        tmp_path,
        """
        function handler(req, res) {
          const doc = `prefix:${req.body}`;
          sink(doc);
        }
        """,
    )
    assert verdict == TAINTED


# -- the JS adapter does not disturb the Python pass --------------------------


def test_python_fixture_still_tainted_through_registry():
    # The registry now holds both adapters; the Python path must be unchanged.
    vuln = os.path.join(REPO, "samples", "vulnerable-app")
    result = _taint_for(vuln)["dep:PyPI:PyYAML"]
    assert result.verdict == TAINTED
    assert result.source == "request.get_data"
    assert result.sink_symbol == "yaml.load"
