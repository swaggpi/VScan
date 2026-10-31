"""Report service -- middle of the reachable-but-safe Jinja2 chain.

``render`` is reached by ``GET /reports/<report_id>``. It fetches server-side
content for the report and asks the templating layer to render it. The only
inputs that reach the Jinja2 sink are the path id and stored content -- never
attacker-controlled request data -- so the chain is reachable but not tainted.
"""

from core import db, templating


def render(report_id):
    """Render the identified report to an HTML fragment."""
    title = "Report " + str(report_id)
    body = db.get_report_body(report_id)
    return templating.render_page(title, body)


def catalog():
    """List the ids of reports available to render."""
    return db.report_ids()
