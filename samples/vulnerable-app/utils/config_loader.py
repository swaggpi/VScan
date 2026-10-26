"""Configuration loading helpers."""

import yaml as y


def load_config(raw):
    """Parse raw YAML configuration text into a Python object.

    The import is aliased (``import yaml as y``) so the scanner's call
    resolution must follow the alias back to the PyYAML dependency.
    """
    return y.load(raw)
