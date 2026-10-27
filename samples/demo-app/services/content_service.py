"""Content-assembly service -- second hop of the ``/reports/<id>`` chain.

Turns a report id into a title and body (here, placeholder content for the
demo) and hands them to the template service for rendering.
"""

from services import template_service


def assemble(report_id):
    """Assemble the title/body for a report and render it to HTML."""
    title = "Report " + str(report_id)
    body = "Generated report for " + str(report_id)
    return template_service.render(title, body)
