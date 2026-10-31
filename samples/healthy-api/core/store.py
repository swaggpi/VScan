"""In-memory note store -- standard-library only.

A deliberately tiny persistence layer (a dict keyed by note id) so the sample
runs with no external services. Insert is upsert; search is a substring match
over title and body.
"""

from __future__ import annotations

_NOTES: dict[str, dict] = {}


def insert(record: dict) -> None:
    """Upsert a note record by its ``id``."""
    _NOTES[record["id"]] = record


def get(note_id: str) -> dict | None:
    """Return the record for ``note_id`` or ``None``."""
    return _NOTES.get(note_id)


def all_records() -> list[dict]:
    """Return all records, newest first by ``created_at``."""
    return sorted(_NOTES.values(), key=lambda r: r.get("created_at", ""), reverse=True)


def search(needle: str) -> list[dict]:
    """Return records whose title or body contains ``needle`` (already lowered)."""
    return [
        r
        for r in all_records()
        if needle in r.get("title", "").lower() or needle in r.get("body", "").lower()
    ]


def delete(note_id: str) -> bool:
    """Delete a record; return whether it existed."""
    return _NOTES.pop(note_id, None) is not None
