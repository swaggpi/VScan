"""Configuration-import controller.

Exposes the public ``POST /configs/import`` route. The handler is a plain
module-level function so the reachability engine can follow the call chain from
this route straight down through the service and parser layers.
"""

from flask import Blueprint, jsonify, request

from services import config_service

bp = Blueprint("config", __name__)


@bp.route("/configs/import", methods=["POST"])
def import_config():
    """Public route: accept a YAML config upload and ingest it."""
    raw = request.get_data(as_text=True)
    result = config_service.ingest(raw)
    return jsonify({"imported": result})
