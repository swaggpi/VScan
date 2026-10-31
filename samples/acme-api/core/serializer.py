"""Serialization helper -- standard-library only, no dependency edge.

Normalizes stored specs to JSON-safe structures. Uses only ``json`` from the
standard library, so it adds no third-party dependency.
"""

import json


def normalize(obj):
    """Return a JSON-round-tripped, JSON-safe copy of ``obj``."""
    try:
        return json.loads(json.dumps(obj, default=str))
    except (TypeError, ValueError):
        return str(obj)
