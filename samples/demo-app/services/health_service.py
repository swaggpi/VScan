"""Health-check service -- the leaf of the ``/health`` chain.

Calls an upstream dependency over HTTP using ``requests``. ``requests`` is a
current, patched version with no known advisory, so although this dependency is
genuinely *reachable* from a public route, it should produce no finding -- the
demo's "reachable but safe" case.
"""

import requests

_UPSTREAM = "https://status.internal.example/health"


def check_upstream():
    """Probe the upstream service and summarise the result."""
    response = requests.get(_UPSTREAM, timeout=2.0)
    return _summarize(response)


def _summarize(response):
    """Reduce an HTTP response to a small JSON-friendly status dict."""
    return {"status": "ok", "upstream_reachable": bool(response)}
