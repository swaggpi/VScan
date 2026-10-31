"""Tiny in-memory document/report store -- no third-party dependency.

A stand-in for a database so the service layer has something concrete to call.
It uses only builtins, so it introduces no dependency edges and keeps the
reachable region fully resolved.
"""

import uuid

from core import serializer

_DOCUMENTS = {}
_REPORTS = {
    "quarterly": "Quarterly summary body.",
    "incident": "Incident review body.",
}


def store_document(spec):
    """Store a parsed document spec and return a fresh id."""
    document_id = uuid.uuid4().hex
    _DOCUMENTS[document_id] = serializer.normalize(spec)
    return document_id


def get_document(document_id):
    """Return a stored document spec, or ``None`` if unknown."""
    return _DOCUMENTS.get(document_id)


def document_ids():
    """Return all stored document ids."""
    return list(_DOCUMENTS)


def get_report_body(report_id):
    """Return the stored body text for a report id (server-side content)."""
    return _REPORTS.get(report_id, "Unknown report.")


def report_ids():
    """Return all known report ids."""
    return list(_REPORTS)
