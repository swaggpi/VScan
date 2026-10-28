"""Configuration loading helper for the Starlette demo (PyYAML sink)."""

import yaml


def load_config(data):
    # fn -> dep edge: config.load_config -> PyYAML  (symbol ``yaml.load``).
    # Carries taint when its caller passes attacker-controlled input.
    return yaml.load(data)
