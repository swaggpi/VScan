"""Regression: distribution-name -> import-module-name aliasing.

``build_import_index`` must link an ``import X`` to the dependency node whose
PyPI *distribution* name differs from its top-level import name (e.g.
``python-dateutil`` -> ``dateutil``), including when they differ only by case
(``RestrictedPython``). Crucially, an alias must only take effect when the repo
actually declares that distribution -- it recovers a missed edge, never invents
one -- so the cardinal soundness rule holds.
"""

from __future__ import annotations

import pytest

from scanner.analyzers.python_analyzer import build_import_index
from scanner.manifests import Dependency


def _dep(name: str, ecosystem: str = "PyPI") -> Dependency:
    return Dependency(
        name=name, version="1.0", ecosystem=ecosystem, source_file="requirements.txt"
    )


# (distribution name as declared, import name the code uses)
ALIAS_CASES = [
    ("python-dateutil", "dateutil"),
    ("psycopg2-binary", "psycopg2"),
    ("PyJWT", "jwt"),
    ("python-dotenv", "dotenv"),
    ("pyopenssl", "OpenSSL"),          # declared lowercase; import is OpenSSL
    ("restrictedpython", "RestrictedPython"),  # differs only by case
    ("msgpack-python", "msgpack"),
    ("python-slugify", "slugify"),
    # the pre-existing entries still hold
    ("PyYAML", "yaml"),
    ("beautifulsoup4", "bs4"),
    ("Pillow", "PIL"),
]


@pytest.mark.parametrize("dist,import_name", ALIAS_CASES)
def test_alias_links_import_to_declared_distribution(dist, import_name):
    index = build_import_index([_dep(dist)])
    assert index.get(import_name) == f"dep:PyPI:{dist}"


def test_alias_does_not_fire_without_the_distribution():
    # Only `requests` is declared; no unrelated alias key may leak into the index.
    index = build_import_index([_dep("requests")])
    for leaked in ("dateutil", "psycopg2", "jwt", "OpenSSL", "yaml", "PIL"):
        assert leaked not in index
    assert index.get("requests") == "dep:PyPI:requests"


def test_plain_normalisation_still_applies():
    # A hyphenated name with no special import mapping normalises by lower + _.
    index = build_import_index([_dep("Flask-RESTful")])
    assert index.get("flask_restful") == "dep:PyPI:Flask-RESTful"


def test_non_pypi_dependencies_are_ignored():
    index = build_import_index([_dep("lodash", ecosystem="npm")])
    assert index == {}
