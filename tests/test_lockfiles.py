"""Modern-lockfile resolution: Python ``uv.lock`` and JavaScript ``bun.lock``.

Both lockfiles carry the FULL resolved tree with exact versions. Without them a
uv/bun project's deps stay at their declared constraints (``>=``/``^``), which
OSV cannot check. These tests prove:

* a ``>=`` (unpinned) direct dep is resolved to its exact locked version, so it
  is no longer unpinned, and an already-``==``-pinned one resolves harmlessly;
* packages the manifest never names become transitive (``direct=False``), with
  the whole tree enumerated;
* PEP 503 normalisation prevents a declared dep being double-emitted as
  transitive, and the root project is not emitted at all;
* ``bun.lock`` JSONC (trailing commas) parses tolerantly;
* malformed/empty lock files fall back to the declared deps without raising;
* the existing requirements.txt (golden-app) and mixed (vulnerable-app) samples
  are unchanged.

All assertions are offline and deterministic (file-only parse passes).
"""

from __future__ import annotations

import os

import pytest

from scanner.manifests import adapter_for
from scanner.scan import scan_repo

SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
)
UV_APP = os.path.join(SAMPLES, "uv-app")
BUN_APP = os.path.join(SAMPLES, "bun-app")
GOLDEN_APP = os.path.join(SAMPLES, "golden-app")
VULNERABLE_APP = os.path.join(SAMPLES, "vulnerable-app")


def _deps_by_id(graph) -> dict[str, object]:
    return {n.id: n for n in graph.nodes_of_kind("dependency")}


# -- Python uv.lock -----------------------------------------------------------


@pytest.fixture(scope="module")
def uv_deps():
    return _deps_by_id(scan_repo(UV_APP))


def test_uv_resolves_unpinned_direct_dep_to_exact_version(uv_deps):
    # pyyaml is declared ">=5.0" (unpinned); uv.lock pins it to 5.4.1.
    node = uv_deps.get("dep:PyPI:pyyaml")
    assert node is not None and node.kind == "dependency"
    assert node.attrs.get("direct") is True
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "5.4.1"  # NOT ">=5.0"
    assert node.attrs.get("declared") == ">=5.0"  # original constraint preserved


def test_uv_resolves_pinned_direct_dep(uv_deps):
    # jinja2 is already "==3.1.2"; resolution is harmless (same version).
    node = uv_deps.get("dep:PyPI:jinja2")
    assert node is not None
    assert node.attrs.get("direct") is True
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "3.1.2"


def test_uv_transitive_is_direct_false(uv_deps):
    # markupsafe is jinja2's dep, resolved only by uv.lock, never declared.
    node = uv_deps.get("dep:PyPI:markupsafe")
    assert node is not None
    assert node.attrs.get("direct") is False
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "2.1.5"


def test_uv_root_project_not_emitted(uv_deps):
    # The root project "uv-app" appears in its own uv.lock as a [[package]];
    # it must be emitted as neither direct nor transitive.
    assert "dep:PyPI:uv-app" not in uv_deps


def test_uv_no_double_emit_exactly_three_deps(uv_deps):
    # pyyaml + jinja2 (direct) + markupsafe (transitive); no duplicates, no root.
    assert set(uv_deps) == {
        "dep:PyPI:pyyaml",
        "dep:PyPI:jinja2",
        "dep:PyPI:markupsafe",
    }


# -- JavaScript bun.lock ------------------------------------------------------


@pytest.fixture(scope="module")
def bun_deps():
    return _deps_by_id(scan_repo(BUN_APP))


def test_bun_jsonc_resolves_declared_dep_to_exact_version(bun_deps):
    # bun.lock has trailing commas (JSONC); express "^4.18.0" -> 4.18.2.
    node = bun_deps.get("dep:npm:express")
    assert node is not None and node.kind == "dependency"
    assert node.attrs.get("direct") is True
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "4.18.2"  # NOT "^4.18.0"
    assert node.attrs.get("declared") == "^4.18.0"


def test_bun_transitive_is_direct_false(bun_deps):
    # accepts is express's dep, resolved only by bun.lock, never declared.
    node = bun_deps.get("dep:npm:accepts")
    assert node is not None
    assert node.attrs.get("direct") is False
    assert node.attrs.get("resolved") is True
    assert node.attrs.get("version") == "1.3.8"


def test_bun_no_double_emit_exactly_two_deps(bun_deps):
    assert set(bun_deps) == {"dep:npm:express", "dep:npm:accepts"}


# -- Malformed lock files fall back without raising ---------------------------


def test_uv_malformed_lock_falls_back_to_declared(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\nversion = "0"\n'
        'dependencies = ["pyyaml>=5.0", "jinja2==3.1.2"]\n'
    )
    (tmp_path / "uv.lock").write_text("this is {{{ not valid toml")
    deps = adapter_for("pyproject.toml").parse(str(pyproject), "pyproject.toml")
    # No transitive enumeration; declared deps survive at their constraints.
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"pyyaml", "jinja2"}
    assert by_name["pyyaml"].resolved is False
    assert by_name["pyyaml"].version == ">=5.0"
    assert all(d.direct for d in deps)


def test_uv_missing_lock_keeps_todays_behavior(tmp_path):
    # pyproject with PEP 621 deps but NO uv.lock: declared-only, unchanged.
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\nversion = "0"\n'
        'dependencies = ["pyyaml>=5.0"]\n'
        '[project.optional-dependencies]\nextra = ["rich>=13"]\n'
    )
    deps = adapter_for("pyproject.toml").parse(str(pyproject), "pyproject.toml")
    # Without a uv.lock, optional-dependencies are NOT collected (today's
    # behavior): only [project].dependencies, unresolved.
    assert [d.name for d in deps] == ["pyyaml"]
    assert deps[0].resolved is False
    assert deps[0].version == ">=5.0"


def test_bun_malformed_lock_falls_back_to_declared(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"express": "^4.18.0"}}'
    )
    (tmp_path / "bun.lock").write_text("{ this is not json at all ")
    pkg = tmp_path / "package.json"
    deps = adapter_for("package.json").parse(str(pkg), "package.json")
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"express"}  # no transitive, no crash
    assert by_name["express"].resolved is False
    assert by_name["express"].version == "^4.18.0"


def test_bun_scoped_package_version_after_last_at(tmp_path):
    # A scoped transitive "@scope/pkg@1.2.3": name is everything before the LAST
    # "@". Declared dep "left-pad" resolves; the scoped pkg becomes transitive.
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"left-pad": "^1.0.0"}}'
    )
    (tmp_path / "bun.lock").write_text(
        '{\n  "lockfileVersion": 1,\n'
        '  "workspaces": { "": { "name": "x",\n'
        '    "dependencies": { "left-pad": "^1.0.0", },\n'
        "  }, },\n"
        '  "packages": {\n'
        '    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-aa=="],\n'
        '    "@scope/pkg": ["@scope/pkg@1.2.3", "", {}, "sha512-bb=="],\n'
        "  },\n"
        "}\n"
    )
    pkg = tmp_path / "package.json"
    deps = adapter_for("package.json").parse(str(pkg), "package.json")
    by_name = {d.name: d for d in deps}
    assert by_name["left-pad"].version == "1.3.0"
    assert by_name["left-pad"].direct is True
    assert by_name["@scope/pkg"].version == "1.2.3"
    assert by_name["@scope/pkg"].direct is False


# -- Existing samples are unchanged -------------------------------------------


def test_golden_app_requirements_unchanged():
    # Plain requirements.txt: every dep direct=True and unresolved (no lockfile).
    deps = _deps_by_id(scan_repo(GOLDEN_APP))
    assert deps  # non-empty
    for node in deps.values():
        assert node.attrs.get("direct") is True
        assert node.attrs.get("resolved") is False
    assert "dep:PyPI:Flask" in deps


def test_vulnerable_app_unchanged():
    # Mixed sample (requirements + package-lock + composer + go.mod): parses and
    # the package-lock still resolves at least one direct dep exactly.
    deps = _deps_by_id(scan_repo(VULNERABLE_APP))
    assert deps
    assert any(n.attrs.get("resolved") is True for n in deps.values())
