"""Demo service: a small, mostly-secure notes/config/report API.

This is a defensive-security demo fixture for the ``VScan`` reachability
engine. There is no exploit code anywhere in this app -- the only thing
"vulnerable" about it is that a few dependency *versions* in
``requirements.txt`` are intentionally outdated.

The app is wired as a normal Flask service: an application object here, with
each feature area living in its own blueprint under ``controllers/``. The
blueprints delegate into ``services/``, which delegate into ``parsers/`` and
``renderers/``. That layering is what makes the call chains genuinely
multi-file and several hops deep.

Public routes (all registered below):

* ``POST /configs/import`` -- import a YAML configuration document.
* ``GET  /reports/<report_id>`` -- render a stored report as HTML.
* ``GET  /health`` -- liveness probe that checks an upstream dependency.
"""

from flask import Flask

from controllers import config_controller, health_controller, report_controller

app = Flask(__name__)
app.register_blueprint(config_controller.bp)
app.register_blueprint(report_controller.bp)
app.register_blueprint(health_controller.bp)


if __name__ == "__main__":  # pragma: no cover
    app.run()
