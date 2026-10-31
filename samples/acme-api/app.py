"""Acme DocVault API -- a document ingest & reporting service.

A defensive-security demo fixture for the ``VScan`` reachability engine. The
app is a realistic, layered Flask service: an application object here that
registers one blueprint per feature area under ``api/``. Each blueprint
delegates into ``services/``, which in turn delegate into the shared
infrastructure in ``core/``. That layering is what gives the call graph genuine
DEPTH (a route is four to five hops from the dependency it ultimately calls) and
BREADTH (several blueprints, ~a dozen routes).

Nothing here is exploit code. The only thing "vulnerable" about the service is
that a number of dependency *versions* in ``requirements.txt`` are intentionally
pinned to old releases with known advisories. What the scanner then shows is
*which* of those old dependencies a public HTTP route can actually reach -- and,
for the one true exploit, that attacker-controlled input flows all the way into
the sink.

Feature areas (blueprints):

* ``api/documents.py``  -- import, fetch and list documents (the flagship path).
* ``api/reports.py``    -- render stored reports to HTML.
* ``api/auth.py``       -- issue and verify session tokens.
* ``api/webhooks.py``   -- fan out event notifications to an internal endpoint.
* ``api/admin.py``      -- operational status and effective configuration.
"""

from flask import Flask

from api import admin, auth, documents, reports, webhooks

app = Flask(__name__)
app.register_blueprint(documents.bp)
app.register_blueprint(reports.bp)
app.register_blueprint(auth.bp)
app.register_blueprint(webhooks.bp)
app.register_blueprint(admin.bp)


if __name__ == "__main__":  # pragma: no cover
    app.run()
