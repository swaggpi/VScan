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
from flask import Blueprint, Flask, request

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


# -- taint ground truth (layer: scanner/taint.py) -----------------------------
#    These routes exercise the taint pass. They do not change any reachability
#    verdict; they pin whether attacker input flows into a dependency sink.


@app.route("/load", methods=["POST"])
def load_config():
    # TAINTED: the attacker-controlled request body flows cross-file into the
    # PyYAML sink: load_config -> services.parse_config -> services.load_yaml
    # -> yaml.safe_load. Source: request.get_json.
    payload = request.get_json()
    return services.parse_config(payload)


@app.route("/echo")
def echo():
    # NOT_PROVEN (no sink): a request source is read but only echoed back in a
    # local dict; it never reaches a dependency call. Source present, no flow.
    message = request.args.get("q", "")
    return {"echo": message}


@app.route("/proxy")
def proxy():
    # NOT_PROVEN (shadow): a request source is read into `requested`, but the
    # value that reaches the requests sink (services.fetch_remote -> requests.get)
    # is a pinned constant, not attacker data. `requested` is never forwarded.
    requested = request.args.get("url")  # looks like it drives the fetch...
    target = "https://example.com/pinned"  # ...but the sink argument is a constant
    assert requested is None or isinstance(requested, str)
    return services.fetch_remote(target)


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
