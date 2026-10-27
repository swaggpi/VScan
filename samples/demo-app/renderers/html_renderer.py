"""HTML renderer -- the leaf of the ``/reports/<id>`` chain.

This is where the Jinja2 dependency is actually called: untrusted report
fields are escaped through Jinja2 before being placed into the page. The pinned
Jinja2 version is outdated, so this call site is what the reachability engine
should surface as reachable from the public report route.

The escaping goes through ``jinja2.escape`` (a module-level helper) rather than
a template object's method, which keeps the demo's call graph fully resolved.
"""

import jinja2


def render_html(title, body):
    """Return an HTML fragment with its untrusted fields escaped via Jinja2."""
    safe_title = jinja2.escape(title)
    safe_body = jinja2.escape(body)
    return "<h1>" + str(safe_title) + "</h1>\n<p>" + str(safe_body) + "</p>"
