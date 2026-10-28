"""Minimal module for the uv transitive-dependency fixture.

The point of this sample is the dependency *tree* resolved from ``uv.lock``, not
the call graph. ``pyyaml`` and ``jinja2`` are the DECLARED (direct) deps from
PEP 621 ``[project].dependencies``; ``markupsafe`` is TRANSITIVE -- resolved only
by ``uv.lock`` (jinja2's dependency) and never named in the manifest.

``pyyaml`` is declared as ``>=5.0`` (unpinned) and ``jinja2`` as ``==3.1.2``;
uv.lock resolves them to the exact versions ``5.4.1`` and ``3.1.2``. See README.md.
"""

from __future__ import annotations

import yaml  # from pyyaml: declared/direct, imported but never called


def load(text: str):
    ...
