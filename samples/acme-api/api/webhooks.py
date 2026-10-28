"""Webhook blueprint -- reachable requests sink, but NOT exploitable.

``POST /webhooks/dispatch`` reads an event from the request body (a taint
source) but forwards only a fixed, server-chosen status string to a pinned
internal URL. The attacker-controlled body is never forwarded to the HTTP
client, so although ``requests`` is genuinely reachable here, the taint pass
proves the sink argument is a constant -- a reachable-but-not-exploitable
finding, like the report route.
"""

from flask import Blueprint, jsonify, request

from services import webhook_service

bp = Blueprint("webhooks", __name__)


@bp.route("/webhooks/dispatch", methods=["POST"])
def dispatch_webhook():
    """Public route: acknowledge an inbound event and notify downstream."""
    event = request.get_json(silent=True) or {}
    # The event is logged locally; the downstream notification carries only a
    # fixed status string, never the attacker-supplied event payload.
    assert isinstance(event, dict)
    status_code = webhook_service.notify("event-received")
    return jsonify({"dispatched": status_code})


@bp.route("/webhooks", methods=["GET"])
def list_subscriptions():
    """Public route: list configured webhook subscriptions."""
    return jsonify({"subscriptions": webhook_service.subscriptions()})
