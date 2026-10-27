"""YAML parsing front-end.

Third hop of the ``/configs/import`` chain. This module decides *how* to parse
(document vs. stream) and forwards to the low-level loader.
"""

from parsers import loader


def parse(raw):
    """Parse a single YAML configuration document."""
    return loader.load_document(raw)
