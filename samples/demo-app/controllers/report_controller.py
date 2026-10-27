"""Report-rendering controller.

Exposes the public ``GET /reports/<report_id>`` route, which renders a stored
report into an HTML fragment. The handler delegates into the report service.
"""

from flask import Blueprint

from services import report_service

bp = Blueprint("report", __name__)


@bp.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    """Public route: render the identified report as HTML."""
    return report_service.build_report(report_id)
