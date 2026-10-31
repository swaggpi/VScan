"""Transitive-dependency support: the full resolved tree is scanned, and the
three-way reachability verdict stays SOUND for transitive deps.

The cardinal rule under test: a transitive dependency (node attr
``direct is False``) is NEVER marked ``unreachable`` -- we do not analyze a
top-level dependency's internals, so whether a reachable top-level dep in turn
reaches a transitive dep is UNKNOWN, hence ``potentially_reachable``. A DIRECT
dep with no call edge in a fully-resolved region must still be ``unreachable``,
so the override keys on the ``direct`` flag, not on "has no incoming call edge".

All assertions are offline and deterministic (scan + graph + reachability are
pure, file-only passes; no network).
"""

from __future__ import annotations

import os

import pytest

from scanner.correlate.report import build_summary
from scanner.reachability import (
    POTENTIALLY_REACHABLE,
    UNREACHABLE,
    compute_reachability,
)
from scanner.scan import scan_repo

SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
)
TRANSITIVE_APP = os.path.join(SAMPLES, "transitive-app")
TRANSITIVE_POETRY = os.path.join(SAMPLES, "transitive-poetry")
TRANSITIVE_PHP = os.path.join(SAMPLES, "transitive-php")
GOLDEN_APP = os.path.join(SAMPLES, "golden-app")

EXPRESS = "dep:npm:express"
MINIMIST = "dep:npm:minimist"
QS = "dep:npm:qs"

# Poetry fixture (pyproject.toml + poetry.lock): requests/PyYAML declared,
# certifi/urllib3 transitive. PyYAML is declared; the lock lists it as "pyyaml".
PY_REQUESTS = "dep:PyPI:requests"
PY_PYYAML = "dep:PyPI:PyYAML"
PY_CERTIFI = "dep:PyPI:certifi"
PY_URLLIB3 = "dep:PyPI:urllib3"

# Composer fixture (composer.json + composer.lock): monolog declared, psr/log
# transitive.
PHP_MONOLOG = "dep:Packagist:monolog/monolog"
PHP_PSRLOG = "dep:Packagist:psr/log"


@pytest.fixture(scope="module")
def graph():
    return scan_repo(TRANSITIVE_APP)


@pytest.fixture(scope="module")
def reach(graph):
    return compute_reachability(graph)


# -- node emission + the direct/transitive flag -------------------------------


def test_transitive_package_becomes_a_dependency_node(graph):
    # The lockfile resolves minimist/qs, which package.json never declares.
    for dep_id in (MINIMIST, QS):
        node = graph.get_node(dep_id)
        assert node is not None and node.kind == "dependency", dep_id
        assert node.attrs.get("direct") is False, dep_id


def test_declared_package_is_direct(graph):
    node = graph.get_node(EXPRESS)
    assert node is not None and node.kind == "dependency"
    assert node.attrs.get("direct") is True
    # The declared dep keeps its lockfile-resolved exact version.
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "4.18.2"


def test_all_three_packages_present(graph):
    found = {n.id for n in graph.nodes_of_kind("dependency")}
    assert {EXPRESS, MINIMIST, QS} <= found


# -- the soundness crux -------------------------------------------------------


def test_transitive_dep_is_potentially_reachable_not_unreachable(reach):
    # THE soundness assertion. minimist/qs have no incoming call edge AND the
    # region is fully resolved (the handler makes no calls) -- yet because they
    # are transitive they must be potentially_reachable, never unreachable.
    assert reach.repo.reachable_region_fully_resolved is True
    for dep_id in (MINIMIST, QS):
        assert reach.repo.verdict_by_dep[dep_id] == POTENTIALLY_REACHABLE, dep_id
        assert reach.repo.verdict_by_dep[dep_id] != UNREACHABLE, dep_id


def test_direct_uncalled_dep_in_resolved_region_is_unreachable(reach):
    # Same region, same edge-absence as minimist/qs -- but express is DIRECT, so
    # it is honestly unreachable. This proves the override keys on `direct`, not
    # on the absence of an incoming call edge.
    assert reach.repo.verdict_by_dep[EXPRESS] == UNREACHABLE


def test_per_entrypoint_verdict_also_honours_transitive(reach):
    # The per-entrypoint verdict map applies the same override.
    assert reach.entrypoints, "fixture must expose at least one entry point"
    for ep in reach.entrypoints:
        for dep_id in (MINIMIST, QS):
            assert ep.verdict_by_dep[dep_id] == POTENTIALLY_REACHABLE, (ep.id, dep_id)


def test_golden_app_direct_deps_stay_unreachable():
    # golden-app has no lockfile -> no transitive deps; its declared deps with
    # no call edge in a fully-resolved region must still be unreachable. This
    # guards the "direct deps keep the plain _classify behavior" promise.
    reach = compute_reachability(scan_repo(GOLDEN_APP))
    assert reach.repo.reachable_region_fully_resolved is True
    for dep_id in (
        "dep:PyPI:urllib3",
        "dep:PyPI:click",
        "dep:PyPI:itsdangerous",
    ):
        assert reach.repo.verdict_by_dep[dep_id] == UNREACHABLE, dep_id
    # And no golden-app dep is transitive.
    reach_graph = scan_repo(GOLDEN_APP)
    assert all(
        n.attrs.get("direct", True) is not False
        for n in reach_graph.nodes_of_kind("dependency")
    )


# -- summary split ------------------------------------------------------------


def test_build_summary_splits_direct_and_transitive(graph):
    summary = build_summary(graph, [])
    assert summary["total_dependencies"] == 3
    assert summary["direct_dependencies"] == 1  # express
    assert summary["transitive_dependencies"] == 2  # minimist, qs
    # total_dependencies is honestly the sum of both.
    assert (
        summary["total_dependencies"]
        == summary["direct_dependencies"] + summary["transitive_dependencies"]
    )


# -- Go // indirect marker ----------------------------------------------------


def test_go_indirect_require_is_transitive(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/tiny\n"
        "\n"
        "go 1.20\n"
        "\n"
        "require github.com/example/directdep v1.0.0\n"
        "\n"
        "require (\n"
        "\tgithub.com/example/indirectdep v2.0.0 // indirect\n"
        "\tgithub.com/example/anotherdirect v3.1.0\n"
        ")\n"
    )
    graph = scan_repo(str(tmp_path))

    direct_node = graph.get_node("dep:Go:github.com/example/directdep")
    assert direct_node is not None and direct_node.attrs.get("direct") is True

    another = graph.get_node("dep:Go:github.com/example/anotherdirect")
    assert another is not None and another.attrs.get("direct") is True

    indirect_node = graph.get_node("dep:Go:github.com/example/indirectdep")
    assert indirect_node is not None and indirect_node.attrs.get("direct") is False


def test_go_indirect_only_changes_flag_not_which_modules(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/tiny\n\n"
        "require (\n"
        "\tgithub.com/a/b v1.0.0\n"
        "\tgithub.com/c/d v2.0.0 // indirect\n"
        ")\n"
    )
    graph = scan_repo(str(tmp_path))
    go_deps = {
        n.id for n in graph.nodes_of_kind("dependency") if n.attrs.get("ecosystem") == "Go"
    }
    assert go_deps == {"dep:Go:github.com/a/b", "dep:Go:github.com/c/d"}


# -- Python poetry.lock transitive deps ---------------------------------------


@pytest.fixture(scope="module")
def poetry_graph():
    return scan_repo(TRANSITIVE_POETRY)


@pytest.fixture(scope="module")
def poetry_reach(poetry_graph):
    return compute_reachability(poetry_graph)


def test_poetry_declared_deps_are_direct(poetry_graph):
    for dep_id in (PY_REQUESTS, PY_PYYAML):
        node = poetry_graph.get_node(dep_id)
        assert node is not None and node.kind == "dependency", dep_id
        assert node.attrs.get("direct") is True, dep_id


def test_poetry_lockfile_only_deps_are_transitive(poetry_graph):
    for dep_id in (PY_CERTIFI, PY_URLLIB3):
        node = poetry_graph.get_node(dep_id)
        assert node is not None and node.kind == "dependency", dep_id
        assert node.attrs.get("direct") is False, dep_id
        # Transitive deps carry the lockfile-resolved exact version.
        assert node.attrs.get("resolved") is True, dep_id


def test_poetry_pep503_normalization_does_not_double_emit(poetry_graph):
    # pyproject declares "PyYAML"; poetry.lock lists it as "pyyaml". The declared
    # node wins (direct=True) and there is NO separate transitive "pyyaml" node.
    assert poetry_graph.get_node(PY_PYYAML) is not None
    assert poetry_graph.get_node("dep:PyPI:pyyaml") is None


def test_poetry_transitive_is_potentially_reachable_not_unreachable(poetry_reach):
    # THE soundness assertion. certifi/urllib3 have no incoming call edge AND the
    # region is fully resolved (the handler makes no calls) -- yet because they
    # are transitive they must be potentially_reachable, never unreachable.
    assert poetry_reach.repo.reachable_region_fully_resolved is True
    for dep_id in (PY_CERTIFI, PY_URLLIB3):
        assert poetry_reach.repo.verdict_by_dep[dep_id] == POTENTIALLY_REACHABLE, dep_id
        assert poetry_reach.repo.verdict_by_dep[dep_id] != UNREACHABLE, dep_id


def test_poetry_direct_uncalled_dep_is_unreachable(poetry_reach):
    # Same region, same edge-absence as certifi/urllib3 -- but requests/PyYAML
    # are DIRECT, so they are honestly unreachable. Proves the override keys on
    # the `direct` flag, not on the absence of an incoming call edge.
    for dep_id in (PY_REQUESTS, PY_PYYAML):
        assert poetry_reach.repo.verdict_by_dep[dep_id] == UNREACHABLE, dep_id


# -- PHP composer.lock transitive deps ----------------------------------------


@pytest.fixture(scope="module")
def php_graph():
    return scan_repo(TRANSITIVE_PHP)


@pytest.fixture(scope="module")
def php_reach(php_graph):
    return compute_reachability(php_graph)


def test_composer_declared_dep_is_direct(php_graph):
    node = php_graph.get_node(PHP_MONOLOG)
    assert node is not None and node.kind == "dependency"
    assert node.attrs.get("direct") is True


def test_composer_lockfile_only_dep_is_transitive(php_graph):
    node = php_graph.get_node(PHP_PSRLOG)
    assert node is not None and node.kind == "dependency"
    assert node.attrs.get("direct") is False
    assert node.attrs.get("resolved") is True


def test_composer_platform_requirement_is_not_a_dep(php_graph):
    # The `php` platform entry in require and the lock must never become a node.
    assert php_graph.get_node("dep:Packagist:php") is None


def test_composer_transitive_is_potentially_reachable_not_unreachable(php_reach):
    assert php_reach.repo.reachable_region_fully_resolved is True
    assert php_reach.repo.verdict_by_dep[PHP_PSRLOG] == POTENTIALLY_REACHABLE
    assert php_reach.repo.verdict_by_dep[PHP_PSRLOG] != UNREACHABLE


def test_composer_direct_uncalled_dep_is_unreachable(php_reach):
    assert php_reach.repo.verdict_by_dep[PHP_MONOLOG] == UNREACHABLE


# -- Python Pipfile + Pipfile.lock transitive deps ----------------------------


def test_pipenv_declared_is_direct_and_lock_only_is_transitive(tmp_path):
    (tmp_path / "Pipfile").write_text(
        "[[source]]\n"
        'url = "https://pypi.org/simple"\n'
        'name = "pypi"\n'
        "\n"
        "[packages]\n"
        'requests = "*"\n'
        "\n"
        "[dev-packages]\n"
    )
    (tmp_path / "Pipfile.lock").write_text(
        '{\n'
        '  "default": {\n'
        '    "requests": {"version": "==2.31.0"},\n'
        '    "certifi": {"version": "==2024.2.2"}\n'
        '  },\n'
        '  "develop": {}\n'
        '}\n'
    )
    graph = scan_repo(str(tmp_path))

    declared = graph.get_node("dep:PyPI:requests")
    assert declared is not None and declared.attrs.get("direct") is True

    transitive = graph.get_node("dep:PyPI:certifi")
    assert transitive is not None and transitive.attrs.get("direct") is False
    assert transitive.attrs.get("resolved") is True
    # The "==" is stripped from the locked version.
    assert transitive.attrs.get("version") == "2024.2.2"


def test_pipenv_pep503_normalization_does_not_double_emit(tmp_path):
    # Declared "PyYAML"; lock lists "pyyaml" -- must not emit a second node.
    (tmp_path / "Pipfile").write_text("[packages]\nPyYAML = \"*\"\n")
    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"pyyaml": {"version": "==6.0.1"}}, "develop": {}}\n'
    )
    graph = scan_repo(str(tmp_path))
    assert graph.get_node("dep:PyPI:PyYAML") is not None
    assert graph.get_node("dep:PyPI:pyyaml") is None
