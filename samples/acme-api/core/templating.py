"""Templating helper -- the Jinja2 sink.

``render_page`` escapes the report body through Jinja2 and assembles a small
HTML fragment. The escaping goes through ``jinja2.escape`` (a module-level
helper) so the call graph stays fully resolved. The inputs are server-side
content, never request data, so this sink is reachable but not tainted.
"""

import jinja2


def render_page(title, body):
    """Return an HTML fragment with its fields escaped via Jinja2."""
    safe_title = jinja2.escape(title)
    safe_body = jinja2.escape(body)
    return "<h1>" + str(safe_title) + "</h1>\n<p>" + str(safe_body) + "</p>"
