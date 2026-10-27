"""Report service -- first hop of the ``/reports/<id>`` chain.

Looks up the report shell for an id and asks the content service to assemble
the renderable pieces.
"""

from services import content_service


def build_report(report_id):
    """Build the HTML body for the report identified by ``report_id``."""
    return content_service.assemble(report_id)
