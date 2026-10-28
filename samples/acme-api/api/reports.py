"""Report blueprint -- reachable, but NOT exploitable.

``GET /reports/<report_id>`` renders a stored report to HTML, reaching the
Jinja2 dependency through the templating layer. Jinja2 is an old, vulnerable
pin, so this route is a genuine *reachable* (and symbol-confirmed) finding -- but
the only value that reaches the sink is the path id and server-side content, not
attacker-controlled request data, so the taint pass correctly declines to call
it exploitable. This is the deliberate contrast to the documents flagship.
"""

from flask import Blueprint

from services import report_service

bp = Blueprint("reports", __name__)


@bp.route("/reports/<report_id>", methods=["GET"])
def render_report(report_id):
    """Public route: render the identified report as an HTML fragment."""
    return report_service.render(report_id)


@bp.route("/reports", methods=["GET"])
def list_reports():
    """Public route: list the available report ids."""
    return {"reports": report_service.catalog()}
