"""Document ingest service -- middle of the flagship chain.

``ingest`` is the first hop below the ``POST /documents/import`` handler. It
forwards the raw upload to ``build_spec`` (a same-module sibling), which hands
it to the config loader in ``core/``. The attacker-controlled upload is passed
through as a plain positional argument at every step, so taint is preserved all
the way to the PyYAML sink.
"""

from core import config_loader, db


def ingest(payload):
    """Parse an uploaded document spec and store it; return its new id.

    ``payload`` is the raw request body. It is forwarded unchanged into
    ``build_spec`` -- this is the hop that keeps the flagship taint flow alive.
    """
    spec = build_spec(payload)
    document_id = db.store_document(spec)
    return document_id


def build_spec(payload):
    """Turn a raw upload into a structured spec via the YAML config loader."""
    return config_loader.load_spec(payload)


def fetch(document_id):
    """Return a previously stored document, or ``None`` if unknown."""
    return db.get_document(document_id)


def list_ids():
    """Return the ids of all stored documents."""
    return db.document_ids()
