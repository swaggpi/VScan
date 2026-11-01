"""Plugin Reports API.

The flagship route ``POST /reports/render`` accepts an attacker-supplied report
template and renders it. The template engine is selected reflectively at request
time (see :mod:`render_service`), so the structural analyzer cannot see which
library actually runs -- the Jinja2 call site is a dynamic dispatch. VScan
therefore marks Jinja2 "not reached" (a deliberately conservative lower bound);
the advisory inferred-edge tier recovers the dynamic path.
"""

from flask import Flask, request

from render_service import render_report

app = Flask(__name__)


@app.route("/reports/render", methods=["POST"])
def render():
    """Public: render an untrusted report template from the request body."""
    template_text = request.get_data(as_text=True)
    return render_report(template_text, {"user": "guest"})


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"ok": True}
