"""Configuration ingest service.

First hop of the ``/configs/import`` call chain. It hands the raw upload to the
validation service and reports how many top-level keys were accepted.
"""

from services import validation_service


def ingest(raw):
    """Validate and parse an uploaded configuration document.

    Returns the number of top-level keys in the parsed configuration.
    """
    config = validation_service.validate(raw)
    if isinstance(config, dict):
        return len(config)
    return 0
