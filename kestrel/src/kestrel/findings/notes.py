# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Append-only finding investigation notes.

SecOps collaboration breadcrumbs — distinct from exceptions, mute,
status, and watchers. Notes never change finding triage state.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.operator import Operator

NOTE_BODY_MAX_CHARS = 4000
NOTES_DETAIL_LIMIT = 20
NOTES_LIST_MAX = 200


class FindingNoteError(ValueError):
    """Raised when a note write cannot proceed. Callers map to HTTP 422."""


def _operator_out(db: Session, operator_id: uuid.UUID | None) -> dict[str, Any] | None:
    if operator_id is None:
        return None
    operator = db.get(Operator, operator_id)
    if operator is None:
        return None
    return {"id": operator.id, "email": operator.email, "display_name": operator.display_name}


def note_out(db: Session, note: FindingNote) -> dict[str, Any]:
    return {
        "id": note.id,
        "finding_id": note.finding_id,
        "body": note.body,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "author": _operator_out(db, note.author_operator_id),
    }


def _validate_body(body: str) -> str:
    cleaned = body.strip()
    if not cleaned:
        raise FindingNoteError("body is required")
    if len(cleaned) > NOTE_BODY_MAX_CHARS:
        raise FindingNoteError(f"body must be at most {NOTE_BODY_MAX_CHARS} characters")
    return cleaned


def list_notes(
    db: Session,
    finding: Finding,
    *,
    limit: int = NOTES_DETAIL_LIMIT,
) -> list[dict[str, Any]]:
    """Newest-first notes for ``finding`` (org-scoped)."""
    cap = max(0, min(limit, NOTES_LIST_MAX))
    if cap == 0:
        return []
    rows = db.scalars(
        select(FindingNote)
        .where(FindingNote.finding_id == finding.id, FindingNote.org_id == finding.org_id)
        .order_by(FindingNote.created_at.desc(), FindingNote.id.desc())
        .limit(cap)
    ).all()
    return [note_out(db, row) for row in rows]


def add_note(
    db: Session,
    *,
    finding: Finding,
    author_operator_id: uuid.UUID,
    body: str,
) -> FindingNote:
    """Append a note. Does not change finding status."""
    cleaned = _validate_body(body)
    note = FindingNote(
        id=uuid.uuid4(),
        org_id=finding.org_id,
        finding_id=finding.id,
        author_operator_id=author_operator_id,
        body=cleaned,
    )
    db.add(note)
    db.flush()
    return note
