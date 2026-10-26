"""A tiny on-disk JSON cache with per-entry TTL.

This lives *outside* the repository (under the user's cache directory) so the
scanner never leaves a tracked artifact behind. It is used by the enrichment
layer for the CISA KEV catalog (~1 day TTL) and for NVD/EPSS lookups.

The cache is deliberately dependency-free (stdlib ``json`` only) and fails
*soft*: a corrupt or unreadable entry is treated as a miss rather than an error,
so a bad cache can never crash a scan.

Location (first match wins):

* ``$VULNREACH_CACHE_DIR``                -- explicit override
* ``$XDG_CACHE_HOME/vulnreach``          -- XDG base-directory spec
* ``~/.cache/vulnreach``                 -- default
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

_ENV_OVERRIDE = "VULNREACH_CACHE_DIR"
_ENV_XDG = "XDG_CACHE_HOME"
_APP = "vulnreach"


def cache_dir() -> Path:
    """Return the cache directory, creating it if necessary.

    Resolved fresh on every call so tests can redirect it via the environment.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        base = Path(override)
    else:
        xdg = os.environ.get(_ENV_XDG)
        base = Path(xdg) / _APP if xdg else Path.home() / ".cache" / _APP
    base.mkdir(parents=True, exist_ok=True)
    return base


def _path_for(key: str) -> Path:
    """Map a logical key to a stable on-disk filename (sha256, hex)."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return cache_dir() / f"{digest}.json"


def get(key: str) -> Any | None:
    """Return the cached value for ``key``, or ``None`` if missing/expired.

    Any read or decode error is swallowed and reported as a miss.
    """
    path = _path_for(key)
    try:
        with path.open(encoding="utf-8") as handle:
            envelope = json.load(handle)
    except (OSError, ValueError):
        return None

    expires = envelope.get("expires")
    if isinstance(expires, (int, float)) and expires < time.time():
        # Expired: best-effort cleanup, then report a miss.
        try:
            path.unlink()
        except OSError:
            pass
        return None
    return envelope.get("value")


def set(key: str, value: Any, *, ttl: float) -> None:
    """Store ``value`` under ``key`` for ``ttl`` seconds. Best-effort (never raises)."""
    envelope = {"expires": time.time() + ttl, "value": value}
    path = _path_for(key)
    try:
        tmp = path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(envelope, handle)
        tmp.replace(path)
    except (OSError, ValueError, TypeError):
        # A cache that cannot be written must not break the scan.
        pass
