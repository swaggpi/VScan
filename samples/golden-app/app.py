"""Golden fixture entry points: every supported route style, plus shadowing
negatives that MUST NOT produce a dependency edge.

Routes (ground truth):
  GET  /decorated   -> decorated   (decorator, default verb)
  POST /submit      -> submit      (decorator with methods=[...])
  GET  /fetch       -> fetch       (decorator, default verb)
  GET  /added       -> added       (imperative app.add_url_rule)
  GET  /api/items   -> list_items  (Blueprint mounted at url_prefix="/api")

Shadowing negatives (ground truth: NO edge to PyYAML):
  transform(yaml)   -> the parameter ``yaml`` shadows the module import, so
                       ``yaml.load`` is a call on the parameter, not the package.
  rebind()          -> a local ``yaml`` is rebound to a different object before
                       ``yaml.load`` is called.
"""

from __future__ import annotations

import yaml  # legitimately shadowed below; see transform()/rebind()
from flask import Blueprint, Flask

import services

app = Flask(__name__)
api = Blueprint("api", __name__)


@app.route("/decorated")
def decorated():
    return services.describe()


@app.route("/submit", methods=["POST"])
def submit():
    raw = "a: 1"
    return services.ingest(raw)


@app.route("/fetch")
def fetch():
    return services.fetch_remote("https://example.com")


def added():
    # Resolvable leaf so the reachable region stays fully resolved (lets the
    # non-routed deps earn a clean `unreachable` verdict). The instance/self
    # method-call boundary is exercised off the routed path, in offline.py.
    return services.describe()


app.add_url_rule("/added", view_func=added)


@api.route("/items")
def list_items():
    return {"items": services.parse_dates(["2020-01-01"])}


app.register_blueprint(api, url_prefix="/api")


# -- shadowing negatives: these define `yaml.load(...)` but on a NON-package
#    binding, so no services.* /dependency edge to PyYAML may be emitted. --------

class _FakeYaml:
    def load(self, _data):
        return None


def transform(yaml):
    # `yaml` is a parameter here, NOT the imported package.
    return yaml.load("{}")


def rebind():
    yaml = _FakeYaml()  # local rebinding shadows the module-level import
    return yaml.load("{}")
