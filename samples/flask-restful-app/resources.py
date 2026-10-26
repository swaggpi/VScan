"""Flask-RESTful ``Resource`` classes, deliberately in a *sibling* file.

The route registrations live in :mod:`app`, so wiring these resources to their
entry points exercises the analyzer's cross-file class-method resolution: the
HTTP verb for each route comes from the verb methods defined here.
"""

from flask_restful import Resource


class UserResource(Resource):
    """A single user. Defines two HTTP verbs -> two routes per mount path."""

    def get(self, id):
        return {"id": id}

    def post(self, id):
        return {"id": id}, 201


class SecretResource(Resource):
    """Only ever registered with a NON-literal path, so it must stay invisible."""

    def get(self):
        return {"secret": True}
