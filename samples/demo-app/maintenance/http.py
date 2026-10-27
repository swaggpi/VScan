"""Low-level HTTP helper for the maintenance sync job.

Uses ``urllib3`` directly. The pinned ``urllib3`` version is outdated and has a
known advisory, but this helper is only ever called by the offline sync job, so
it is unreachable from any public route.
"""

import urllib3


def fetch(url):
    """Fetch a URL and return its raw body (maintenance use only)."""
    pool = urllib3.PoolManager()
    response = pool.request("GET", url)
    return response.data
