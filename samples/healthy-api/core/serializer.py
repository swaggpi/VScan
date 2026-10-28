"""JSON serialization helpers backed by orjson.

A thin, fast round-trip used to normalize stored records into JSON-safe dicts
before they leave the service. orjson is a current, well-maintained dependency
with no known advisories -- a clean edge in the reachability graph.
"""

from __future__ import annotations

import orjson


def to_json(obj: object) -> bytes:
    """Serialize ``obj`` to compact JSON bytes (orjson)."""
    return orjson.dumps(obj)


def to_jsonable(obj: object) -> dict:
    """Round-trip ``obj`` through orjson into a plain JSON-safe dict."""
    return orjson.loads(orjson.dumps(obj))
