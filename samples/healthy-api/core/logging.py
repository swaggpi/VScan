"""Structured logging backed by structlog.

Configured once at startup; every module gets a bound logger via
``get_logger``. structlog is a current, well-maintained dependency with no
known advisories.
"""

from __future__ import annotations

import structlog


def configure_logging() -> None:
    """Configure structlog for JSON-ish key/value output."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.KeyValueRenderer(key_order=["event"]),
        ]
    )


def get_logger(name: str):
    """Return a bound structlog logger for ``name``."""
    return structlog.get_logger(name)
