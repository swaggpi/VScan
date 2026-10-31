"""Webhook service -- middle of the reachable-but-safe requests chain.

``notify`` forwards a fixed status message to the HTTP client in ``core/``. The
value it passes is server-chosen, so although ``requests`` is reachable from the
webhook route, no attacker input reaches the HTTP sink.
"""

from core import http_client


def notify(message):
    """Post a status message to the internal notification endpoint."""
    return http_client.post_status(message)


def subscriptions():
    """Return the list of configured webhook subscriptions (static demo data)."""
    return ["billing", "audit", "search-index"]
