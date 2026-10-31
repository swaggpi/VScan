"""Configuration -- standard-library only, no third-party dependency.

Reads a handful of settings from the environment with safe defaults. Reaching
this module adds breadth to the graph without touching any external sink.
"""

from __future__ import annotations

import os

_DEFAULT_WEBHOOK_BASE = "http://notifications.internal/hooks"
_DEFAULT_TIMEOUT = 5.0


def webhook_url(target: str) -> str:
    """Build the internal notification URL for a share ``target``."""
    base = os.environ.get("SCRIBE_WEBHOOK_BASE", _DEFAULT_WEBHOOK_BASE).rstrip("/")
    return f"{base}/{target.strip('/')}"


def http_timeout() -> float:
    """Return the outbound HTTP timeout in seconds."""
    try:
        return float(os.environ.get("SCRIBE_HTTP_TIMEOUT", _DEFAULT_TIMEOUT))
    except ValueError:
        return _DEFAULT_TIMEOUT


def describe() -> dict:
    """Return a non-sensitive summary of the effective configuration."""
    return {
        "env": os.environ.get("SCRIBE_ENV", "development"),
        "webhook_base": os.environ.get("SCRIBE_WEBHOOK_BASE", _DEFAULT_WEBHOOK_BASE),
        "http_timeout": http_timeout(),
    }
