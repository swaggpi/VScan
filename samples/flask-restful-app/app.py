"""A small Flask-RESTful app exercising registry-style route registration.

Registration here is almost entirely NON-decorator, which the analyzer must now
follow soundly:

* ``api.add_resource(UserResource, "/users/<id>")`` -- verbs come from the
  Resource class defined in :mod:`resources` (cross-file);
* ``app.add_url_rule("/health", view_func=health_view)`` -- imperative Flask
  rule wired to a function in :mod:`blueprints`;
* ``app.register_blueprint(widgets_bp)`` -- the blueprint's own ``url_prefix``
  composes onto its routes.

Two registrations MUST NOT produce an entry point (cardinal rule): a non-literal
path, and an ``add_resource`` on a receiver that is not a Flask-RESTful ``Api``.
"""

import os

from flask import Flask
from flask_restful import Api

from blueprints import health_view, widgets_bp
from resources import SecretResource, UserResource

app = Flask(__name__)
api = Api(app)

# Registry-style resource: GET + POST /users/<id> (verbs from UserResource).
api.add_resource(UserResource, "/users/<id>")

# Imperative Flask rule wired to a function handler in another file.
app.add_url_rule("/health", view_func=health_view, methods=["GET"])

# Blueprint whose url_prefix ("/api/v1") must compose onto "/widgets".
app.register_blueprint(widgets_bp)


# --- Negative cases: neither of these may yield an entrypoint ---------------

# Non-literal path: the Resource resolves, but the path is dynamic, so the
# cardinal rule forbids emitting any route.
_dynamic_path = os.environ.get("SECRET_ROUTE", "/secret")
api.add_resource(SecretResource, _dynamic_path)


class NotAnApi:
    """Looks like a registrar by method name only -- it is not an Api."""

    def add_resource(self, cls, path):
        return None


not_api = NotAnApi()
not_api.add_resource(UserResource, "/should-not-appear")


if __name__ == "__main__":
    app.run()
