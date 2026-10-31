"""Offline config-feed sync job -- uses urllib3, not reachable from any route.

``run_sync`` is a cron/operator entry point guarded by ``__main__``. No public
route calls it, so the old ``urllib3`` it reaches is unreachable from the web
service.
"""

import urllib3

_FEED_URL = "https://feeds.internal.acme.example/configs.json"


def run_sync():
    """Fetch the latest config feed (run from cron, not from a request)."""
    pool = urllib3.PoolManager()
    response = pool.request("GET", _FEED_URL)
    return response.data


if __name__ == "__main__":  # pragma: no cover
    run_sync()
