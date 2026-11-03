"""Webhook delivery (requests).

Unlike the other services, ``requests.get`` is called directly, so static
analysis *does* resolve it -- requests shows as genuinely "reachable". The URL
comes straight from the caller with no allow-list, so this is a server-side
request forgery sink (SSRF): an attacker can point delivery at internal hosts.
"""

import requests  # requests 2.19.1 -- called directly below


def deliver_report(callback_url):
    """POST-fetch a caller-supplied callback URL (no allow-list -> SSRF)."""
    response = requests.get(callback_url, timeout=5)
    return {"status": response.status_code}
