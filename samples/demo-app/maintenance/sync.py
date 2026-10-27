"""Offline config-feed sync job.

``run_sync`` is an operator/cron entry point -- it is invoked from the command
line (see the ``__main__`` guard), never from any HTTP route. Because no public
entry point calls it, everything it reaches (including the old ``urllib3``) is
*not reachable* from the running web service.
"""

from maintenance import http

_FEED_URL = "https://feeds.internal.example/configs.json"


def run_sync():
    """Fetch the latest config feed. Run from cron, not from a web request."""
    payload = http.fetch(_FEED_URL)
    return payload


if __name__ == "__main__":  # pragma: no cover
    run_sync()
