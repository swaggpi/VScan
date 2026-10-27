"""Tests for the stdlib ``.env`` loader."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from scanner.dotenv import load_dotenv

_KEYS = ("DOTENV_A", "DOTENV_B", "DOTENV_C", "DOTENV_D", "DOTENV_E")


@pytest.fixture(autouse=True)
def _clean_env() -> Iterator[None]:
    """Clear the test keys before and after, since the loader writes os.environ."""
    for key in _KEYS:
        os.environ.pop(key, None)
    yield
    for key in _KEYS:
        os.environ.pop(key, None)


def test_loads_keys_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("DOTENV_A=one\nDOTENV_B=two\n")
    monkeypatch.chdir(tmp_path)
    load_dotenv()
    assert os.environ["DOTENV_A"] == "one"
    assert os.environ["DOTENV_B"] == "two"


def test_existing_env_not_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    env.write_text("DOTENV_A=from-file\nDOTENV_B=file-b\n")
    monkeypatch.setenv("DOTENV_A", "explicit")
    load_dotenv(str(env))
    assert os.environ["DOTENV_A"] == "explicit"
    assert os.environ["DOTENV_B"] == "file-b"


def test_export_quotes_comments_blank_lines(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "# a comment\n"
        "\n"
        "export DOTENV_A=exported\n"
        '  DOTENV_B = "double quoted"  \n'
        "DOTENV_C='single quoted'\n"
        "DOTENV_D=a=b\n"
    )
    load_dotenv(str(env))
    assert os.environ["DOTENV_A"] == "exported"
    assert os.environ["DOTENV_B"] == "double quoted"
    assert os.environ["DOTENV_C"] == "single quoted"
    assert os.environ["DOTENV_D"] == "a=b"


def test_malformed_lines_skipped(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("no equals sign\n=novalue\nbad key=x\nDOTENV_E=ok\n")
    load_dotenv(str(env))
    assert os.environ["DOTENV_E"] == "ok"
    assert "bad key" not in os.environ


def test_missing_or_unreadable_file_is_noop(tmp_path: Path) -> None:
    load_dotenv(str(tmp_path / "does-not-exist"))
    load_dotenv(str(tmp_path))  # a directory: read error is swallowed
    bad = tmp_path / ".env"
    bad.write_bytes(b"\xff\xfe\x00bad")
    load_dotenv(str(bad))
