"""Business logic reached across files from the route handlers in app.py.

Every dependency call in this module is a KNOWN edge the analyzer must resolve
(see README.md for the full ground-truth table):

  load_yaml    -> PyYAML            via ``import yaml`` + ``yaml.safe_load``
  fetch_remote -> requests          via ``import requests`` + ``requests.get``
  parse_dates  -> python-dateutil   via ``from dateutil import parser as dtp``
                                     + ``dtp.parse`` (aliased-from import AND a
                                     distribution/import name mismatch)
"""

from __future__ import annotations

import yaml
import requests
from dateutil import parser as dtp


def describe() -> str:
    """Leaf handler for GET /decorated; reaches no dependency."""
    return "golden-app"


def ingest(raw: str):
    """Reached by POST /submit; delegates to load_yaml (fn -> fn, same file)."""
    data = load_yaml(raw)
    return {"parsed": data}


def load_yaml(raw: str):
    # fn -> dep edge: services.load_yaml -> PyYAML  (symbol yaml.safe_load)
    return yaml.safe_load(raw)


def parse_config(raw):
    # Reached by POST /load; forwards its argument into the PyYAML sink via
    # load_yaml (fn -> fn, same file). Carries taint when its caller passes
    # attacker input.
    return load_yaml(raw)


def fetch_remote(url: str) -> str:
    # fn -> dep edge: services.fetch_remote -> requests  (symbol requests.get)
    return requests.get(url).text


def parse_dates(items):
    # fn -> dep edge: services.parse_dates -> python-dateutil (aliased + mismatch)
    return [dtp.parse(i) for i in items]


def persist(record):
    """Leaf of the Store.save chain; reaches no dependency."""
    return record
