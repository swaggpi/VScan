"""Template rendering with a reflectively-chosen engine (Jinja2).

``jinja2`` is imported statically (so the dependency is declared and visible),
but the ``jinja2.Environment`` constructor is reached only through ``getattr``.
Static call resolution records that as an unresolved call and never draws a
``calls`` edge to Jinja2 -- which is why Jinja2 shows as "not reached" even
though an attacker-controlled template flows straight into it at runtime.
"""

import jinja2  # Jinja2 2.10 -- imported here, invoked only via getattr below


def render_report(template_text, context):
    """Render an untrusted template. Delegates to a reflectively-built engine."""
    engine = _make_engine()
    template = engine.from_string(template_text)
    return template.render(context)


def _make_engine():
    # Reflective construction: the ``jinja2.Environment`` call is hidden behind
    # getattr, so the structural scan cannot resolve it to Jinja2. autoescape is
    # off, so an attacker-controlled template is server-side template injection.
    environment_cls = getattr(jinja2, "Environment")
    return environment_cls(autoescape=False)
