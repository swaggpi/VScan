"""Input-validation service.

Second hop of the ``/configs/import`` chain. It performs cheap structural
checks on the raw upload before parsing, then delegates the actual parse to the
YAML parser. The checks use only builtins so the call graph stays fully
resolved.
"""

from parsers import yaml_parser

_MAX_BYTES = 1_000_000


def validate(raw):
    """Reject obviously bad uploads, then parse the document."""
    if not isinstance(raw, str):
        raise ValueError("configuration upload must be text")
    if len(raw) > _MAX_BYTES:
        raise ValueError("configuration upload too large")
    return yaml_parser.parse(raw)
