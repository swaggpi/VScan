"""Shared pytest fixtures: scan the sample app once per session."""

from __future__ import annotations

import os

import pytest

from scanner.scan import scan_repo

SAMPLE_APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "vulnerable-app",
)


@pytest.fixture(scope="session")
def graph():
    return scan_repo(SAMPLE_APP)
