"""Low-level YAML loader -- the leaf of the ``/configs/import`` chain.

This is where the PyYAML dependency is actually called. The pinned PyYAML
version is outdated, so this call site is exactly what the reachability engine
should surface as reachable from the public import route.
"""

import yaml


def load_document(raw):
    """Load a YAML document into a Python object via PyYAML."""
    return yaml.load(raw)
