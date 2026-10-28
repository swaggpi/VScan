"""Notes router -- the primary surface of the service.

CRUD over notes, plus a share hook and a search route. Each handler delegates
straight into ``services.note_service``; none of them touch a dependency
directly. The chains below are what give the graph its depth, e.g.::

    POST /notes
      -> note_service.create_note(payload)      # api -> services
      -> store.insert(record)                    # services -> core (store)
      -> serializer.to_json(record)              # services -> core (orjson)

    POST /notes/{note_id}/share
      -> note_service.share_note(note_id, target)
      -> link_service.notify(url, record)        # services -> core (httpx)

Nothing here is attacker-dangerous: bodies are validated by Pydantic models and
only ever stored, serialized, or forwarded to a configured internal endpoint.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services import note_service

router = APIRouter(prefix="/notes", tags=["notes"])


class NoteIn(BaseModel):
    """Incoming note payload (validated by Pydantic v2)."""

    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=20_000)
    tags: list[str] = Field(default_factory=list)


class ShareIn(BaseModel):
    """Share request: the internal endpoint to notify about a note."""

    target: str = Field(min_length=1)


@router.get("")
def list_notes():
    """Public route: list all stored notes (newest first)."""
    return {"notes": note_service.list_notes()}


@router.post("", status_code=201)
def create_note(payload: NoteIn):
    """Public route: create a note from a validated payload."""
    note = note_service.create_note(payload.model_dump())
    return {"note": note}


@router.get("/search")
def search_notes(q: str = ""):
    """Public route: full-text-ish search across titles and bodies."""
    return {"query": q, "notes": note_service.search_notes(q)}


@router.get("/{note_id}")
def get_note(note_id: str):
    """Public route: fetch a single note by id."""
    note = note_service.get_note(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="note not found")
    return {"note": note}


@router.put("/{note_id}")
def update_note(note_id: str, payload: NoteIn):
    """Public route: replace a note's contents."""
    note = note_service.update_note(note_id, payload.model_dump())
    if note is None:
        raise HTTPException(status_code=404, detail="note not found")
    return {"note": note}


@router.delete("/{note_id}", status_code=204)
def delete_note(note_id: str):
    """Public route: delete a note by id."""
    if not note_service.delete_note(note_id):
        raise HTTPException(status_code=404, detail="note not found")
    return None


@router.post("/{note_id}/share")
def share_note(note_id: str, payload: ShareIn):
    """Public route: notify a configured internal endpoint about a note."""
    result = note_service.share_note(note_id, payload.target)
    if result is None:
        raise HTTPException(status_code=404, detail="note not found")
    return {"shared": result}
