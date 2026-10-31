"""Minimal Flask app for the poetry transitive-dependency fixture.

The point of this sample is the dependency *tree*, not the call graph:
``requests`` and ``PyYAML`` are the only DECLARED deps (``pyproject.toml`` +
``[tool.poetry.dependencies]``), while ``certifi`` and ``urllib3`` are
TRANSITIVE -- resolved only by ``poetry.lock`` and never named in the manifest.

``requests`` is imported but never called, and the routed handler body makes NO
calls, so the reachable region is fully resolved. In that region the DIRECT,
uncalled ``requests``/``PyYAML`` deps are honestly ``unreachable``, while the
TRANSITIVE ``certifi``/``urllib3`` stay ``potentially_reachable``: same region,
same edge-absence -- the verdict split can only come from the ``direct`` flag.
See README.md.
"""

from __future__ import annotations

import requests  # declared/direct, imported but never called
from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    status = "ok"
    return status
