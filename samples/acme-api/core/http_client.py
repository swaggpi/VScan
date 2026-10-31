"""HTTP client helper -- the requests sink.

``post_status`` posts to a fixed internal URL. It is reachable from the webhook
route, but the only value it ever sends is a server-chosen status string, so no
attacker input reaches ``requests``.
"""

import requests

_NOTIFY_URL = "https://hooks.internal.acme.example/ingest"


def post_status(message):
    """POST a status message to the internal notification endpoint."""
    response = requests.post(_NOTIFY_URL, data={"status": message}, timeout=2.0)
    return response.status_code
