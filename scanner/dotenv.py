"""Minimal ``.env`` loader (stdlib only).

Lets ``vulnreach`` pick up ``LLM_*``, ``NVD_API_KEY`` and ``VULNREACH_CACHE_DIR``
from a local ``.env`` file without adding a dependency.
"""

from __future__ import annotations

import os


def _parse_line(line: str) -> tuple[str, str] | None:
    """Parse one ``[export ]KEY=VALUE`` line; return ``None`` if unusable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export ") or line.startswith("export\t"):
        line = line[len("export") :].lstrip()
    key, sep, value = line.partition("=")
    key = key.strip()
    if not sep or not key or any(c.isspace() for c in key):
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return key, value


def load_dotenv(path: str = ".env") -> None:
    """Load ``KEY=VALUE`` pairs from ``path`` into ``os.environ``.

    Variables already present in the environment are never overridden, so an
    explicit shell export wins over the file. A missing or unreadable file and
    malformed lines are silently ignored; this never raises.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return
    for line in lines:
        parsed = _parse_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key not in os.environ:
            os.environ[key] = value
