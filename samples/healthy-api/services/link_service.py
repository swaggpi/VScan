"""Link / notification service -- the one outbound-HTTP path.

Posts a compact JSON notification to an internal endpoint when a note is
shared. This is the single route-reachable ``httpx`` call in the app; the URL
is taken from configuration and the body is a serialized note, so there is no
attacker-controlled request forgery here -- just a clean, modern HTTP client.
"""

from __future__ import annotations

import httpx

from core import config
from core.logging import get_logger

log = get_logger(__name__)


def notify(target: str, payload: dict) -> bool:
    """POST ``payload`` to the configured webhook base for ``target``.

    Returns whether the endpoint accepted the notification. Network errors are
    swallowed into a ``False`` so a flaky webhook never breaks a share.
    """
    url = config.webhook_url(target)
    try:
        with httpx.Client(timeout=config.http_timeout()) as client:
            response = client.post(url, json=payload)
        return response.is_success
    except httpx.HTTPError:
        log.warning("share.delivery_failed", target=target)
        return False
