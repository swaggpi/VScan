"""Plugin Reports API.

A reporting service with a pluggable, reflectively-dispatched engine. Every
library that touches untrusted input is reached through ``getattr`` or a
registry lookup, so static call resolution leaves those calls unresolved and
VScan marks the affected dependencies "not reached" (a deliberately conservative
lower bound). The advisory inferred-edge tier recovers the dynamic paths and
surfaces the dependencies as *likely* reachable, and the attack-surface review
flags the code-level issues in these handlers.

Routes are documented as public or internal in ``README.md``; the exposure tier
reads that to tell internet-facing endpoints from admin-only ones.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request

from render_service import render_report
from import_service import load_report_spec
from export_service import export_report_xml
from webhook_service import deliver_report

app = Flask(__name__)


@app.route("/reports/render", methods=["POST"])
def render():
    """Public. Render a report from an attacker-supplied template (SSTI)."""
    template_text = request.get_data(as_text=True)
    return render_report(template_text, {"user": "guest"})


@app.route("/reports/import", methods=["POST"])
def import_report():
    """Public. Import a report spec from attacker-supplied YAML."""
    spec = load_report_spec(request.get_data())
    return {"imported": bool(spec)}


@app.route("/reports/export", methods=["POST"])
def export_report():
    """Public. Re-serialize an attacker-supplied XML report (XXE)."""
    return export_report_xml(request.get_data())


@app.route("/reports/search", methods=["GET"])
def search_reports():
    """Public. Search reports by title."""
    term = request.args.get("q", "")
    conn = sqlite3.connect(":memory:")
    # Attacker-controlled term concatenated straight into SQL.
    query = "SELECT id, title FROM reports WHERE title LIKE '%" + term + "%'"
    return {"rows": [list(r) for r in conn.execute(query).fetchall()]}


@app.route("/reports/attachment", methods=["GET"])
def attachment():
    """Public. Download a report attachment by name."""
    name = request.args.get("name", "")
    # Attacker-controlled name joined to the reports dir without sanitisation.
    path = os.path.join("/srv/reports", name)
    with open(path) as handle:
        return handle.read()


@app.route("/webhooks/deliver", methods=["POST"])
def deliver():
    """Public. Deliver a rendered report to a caller-supplied callback URL."""
    callback_url = request.get_data(as_text=True)
    return deliver_report(callback_url)


@app.route("/reports/rebuild", methods=["POST"])
def rebuild():
    """Public. Rebuild the report cache by running a named build task."""
    task = request.get_data(as_text=True)
    # Task name passed straight to a shell (OS command injection).
    output = subprocess.check_output("report-maint " + task, shell=True)
    return {"output": output.decode("utf-8", "replace")}


@app.route("/healthz", methods=["GET"])
def healthz():
    """Public liveness probe."""
    return {"status": "ok"}
