"""Template service -- third hop of the ``/reports/<id>`` chain.

Selects the HTML renderer for report output. Keeping this indirection in its
own module is what makes the chain to the templating dependency genuinely
multi-file.
"""

from renderers import html_renderer


def render(title, body):
    """Render a report title/body pair to an HTML fragment."""
    return html_renderer.render_html(title, body)
