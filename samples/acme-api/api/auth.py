"""Auth blueprint -- reachable, reaches no vulnerable dependency.

The login/verify routes exercise the service layer but the auth service uses
only the Python standard library (``hashlib``/``hmac``), so these routes reach
no third-party dependency at all. They add realistic breadth to the entry-point
list without widening the vulnerable surface.
"""

from flask import Blueprint, jsonify, request

from services import auth_service

bp = Blueprint("auth", __name__)


@bp.route("/auth/login", methods=["POST"])
def login():
    """Public route: exchange credentials for a signed session token."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "anonymous")
    token = auth_service.issue_token(username)
    return jsonify({"token": token})


@bp.route("/auth/verify", methods=["POST"])
def verify():
    """Public route: check that a presented session token is well-formed."""
    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    return jsonify({"valid": auth_service.verify_token(token)})
