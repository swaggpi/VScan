"""Liveness/health controller.

Exposes the public ``GET /health`` route. This path reaches the ``requests``
dependency (a live upstream check) -- which is current and carries no advisory,
so it is a good example of a *reachable but safe* dependency.
"""

from flask import Blueprint, jsonify

from services import health_service

bp = Blueprint("health", __name__)


@bp.route("/health", methods=["GET"])
def health():
    """Public route: report liveness plus upstream reachability."""
    status = health_service.check_upstream()
    return jsonify(status)
