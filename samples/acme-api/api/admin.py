"""Admin blueprint -- reaches the YAML loader, but with a constant.

``GET /admin/config`` returns the service's effective configuration. It reaches
the very same ``config_loader`` (and therefore PyYAML) as the flagship import
route -- but it parses a fixed, bundled default-config string, not request data.
So PyYAML is reachable from this route too, yet this path carries no taint: the
exploit lives only on ``POST /documents/import``. This makes the funnel honest
-- a sink can be reached many ways and still be exploitable from only one.
"""

from flask import Blueprint, jsonify

from services import admin_service

bp = Blueprint("admin", __name__)


@bp.route("/admin/status", methods=["GET"])
def status():
    """Public route: report service status counters."""
    return jsonify(admin_service.status_report())


@bp.route("/admin/config", methods=["GET"])
def effective_config():
    """Public route: return the effective (default) configuration."""
    return jsonify({"config": admin_service.effective_config()})
