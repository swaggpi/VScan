"""Regression guard for the dashboard's default demo fixture (samples/acme-api).

Pins the ground truth that makes the demo tell its story so it cannot silently
rot: the flagship ``POST /documents/import`` chain is proven tainted into the
PyYAML sink, while the other reachable deps (Jinja2, requests) are reachable but
NOT tainted. Everything here uses the offline ``compute_reachability`` /
``compute_taint`` path -- taint and reachability need no network. CVE counts
(which need OSV) are deliberately out of scope here.
"""

from __future__ import annotations

import os

import pytest

from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.taint import compute_taint

APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "acme-api",
)


@pytest.fixture(scope="module")
def graph():
    return scan_repo(APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


@pytest.fixture(scope="module")
def taint(graph, reach):
    return compute_taint(graph, reach, APP)


# -- reachable set: the funnel must narrow (several reachable, not everything) --

REACHABLE_DEPS = {
    "dep:PyPI:Flask",
    "dep:PyPI:PyYAML",
    "dep:PyPI:Jinja2",
    "dep:PyPI:requests",
}

# Vulnerable deps that must stay OUT of the reachable set (off-route only).
NON_REACHABLE_DEPS = {
    "dep:PyPI:urllib3",
    "dep:PyPI:paramiko",
    "dep:PyPI:Pillow",
    "dep:PyPI:lxml",
    "dep:PyPI:cryptography",
}


def test_reachable_deps_exactly_match(reach):
    reached = {d["id"] for d in reach.repo.reachable_deps}
    assert reached == REACHABLE_DEPS


def test_off_route_deps_are_not_reachable(reach):
    reached = {d["id"] for d in reach.repo.reachable_deps}
    assert reached.isdisjoint(NON_REACHABLE_DEPS)


def test_more_than_one_reachable_dep(reach):
    # The funnel story depends on there being several reachable deps but only
    # one exploitable -- a single reachable dep would make the contrast vacuous.
    assert len(reach.repo.reachable_deps) > 1


# -- taint: exactly one exploitable dep, and it is the flagship ---------------


def test_exactly_one_tainted_dep(taint):
    tainted = {dep_id for dep_id, res in taint.items() if res.verdict == "tainted"}
    assert tainted == {"dep:PyPI:PyYAML"}


def test_flagship_pyyaml_tainted_with_full_proven_evidence(taint):
    result = taint["dep:PyPI:PyYAML"]
    assert result.verdict == "tainted"
    assert result.source == "request.get_data"
    assert result.sink_symbol == "yaml.full_load"
    assert result.entrypoint == "POST /documents/import"
    assert result.path == [
        "ep:POST:/documents/import",
        "fn:api/documents.py:import_document",
        "fn:services/document_service.py:ingest",
        "fn:services/document_service.py:build_spec",
        "fn:core/config_loader.py:load_spec",
        "fn:core/config_loader.py:parse_yaml",
        "dep:PyPI:PyYAML",
    ]


def test_reachable_contrast_deps_are_not_tainted(taint):
    # Jinja2 and requests are reachable (see REACHABLE_DEPS) but must NOT be
    # tainted -- this is the deliberate "reachable but not exploitable" contrast.
    for dep_id in ("dep:PyPI:Jinja2", "dep:PyPI:requests"):
        result = taint.get(dep_id)
        assert result is not None, dep_id
        assert result.verdict == "not_proven", dep_id
