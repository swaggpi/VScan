"""Note service -- the heart of the business logic.

Sits between the ``api.notes`` handlers and the ``core`` infrastructure. It
owns the small amount of domain logic (id + timestamp assignment, search
matching, share orchestration) and delegates persistence to ``core.store``,
serialization to ``core.serializer``, and outbound notifications to
``services.link_service``.
"""

from __future__ import annotations

import uuid

from dateutil import tz
from datetime import datetime

from core import serializer, store
from core.logging import get_logger
from services import link_service

log = get_logger(__name__)


def _now_iso() -> str:
    """Return a timezone-aware ISO-8601 timestamp (via python-dateutil)."""
    return datetime.now(tz=tz.tzutc()).isoformat()


def list_notes() -> list[dict]:
    """Return all stored notes, newest first, as JSON-safe dicts."""
    records = store.all_records()
    return [serializer.to_jsonable(r) for r in records]


def create_note(payload: dict) -> dict:
    """Create and store a note from an already-validated payload."""
    record = {
        "id": uuid.uuid4().hex,
        "title": payload["title"],
        "body": payload.get("body", ""),
        "tags": payload.get("tags", []),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    store.insert(record)
    log.info("note.created", note_id=record["id"])
    return serializer.to_jsonable(record)


def get_note(note_id: str) -> dict | None:
    """Return a single note by id, or ``None`` if unknown."""
    record = store.get(note_id)
    return serializer.to_jsonable(record) if record is not None else None


def update_note(note_id: str, payload: dict) -> dict | None:
    """Replace a note's contents; return the updated note or ``None``."""
    record = store.get(note_id)
    if record is None:
        return None
    record.update(
        title=payload["title"],
        body=payload.get("body", ""),
        tags=payload.get("tags", []),
        updated_at=_now_iso(),
    )
    store.insert(record)
    log.info("note.updated", note_id=note_id)
    return serializer.to_jsonable(record)


def delete_note(note_id: str) -> bool:
    """Delete a note; return whether it existed."""
    removed = store.delete(note_id)
    if removed:
        log.info("note.deleted", note_id=note_id)
    return removed


def search_notes(query: str) -> list[dict]:
    """Return notes whose title or body contains ``query`` (case-insensitive)."""
    needle = query.strip().lower()
    hits = store.search(needle) if needle else store.all_records()
    return [serializer.to_jsonable(r) for r in hits]


def share_note(note_id: str, target: str) -> dict | None:
    """Notify a configured internal endpoint that a note was shared."""
    record = store.get(note_id)
    if record is None:
        return None
    payload = serializer.to_jsonable(record)
    delivered = link_service.notify(target, payload)
    log.info("note.shared", note_id=note_id, delivered=delivered)
    return {"note_id": note_id, "delivered": delivered}
