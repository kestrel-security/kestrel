# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding status transitions and the exception lifecycle.

`apply_status_transition` keeps `resolved_at` and the mute fields consistent
with the new status; every status write (API, pipeline, mute, lifecycle)
goes through it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Exception_, Finding, FindingStatus
from kestrel.findings.investigation._common import _operator_out


class FindingInvestigationError(ValueError):
    """Raised when a status/assignment/exception write cannot proceed.
    Callers map this to HTTP 400/422."""


def parse_finding_status(raw: str) -> FindingStatus:
    try:
        return FindingStatus(raw)
    except ValueError as exc:
        allowed = ", ".join(s.value for s in FindingStatus)
        raise FindingInvestigationError(f"invalid status '{raw}'; expected one of: {allowed}") from exc


def apply_status_transition(finding: Finding, new_status: FindingStatus, *, now: datetime | None = None) -> None:
    """Updates status and keeps `resolved_at` / mute fields consistent with triage.

    Auto-resolve in the evaluation pipeline sets `resolved_at` the same way;
    reopen / suppress / exception / mute clear it so a later resolve is unambiguous.
    Leaving ``muted`` clears ``muted_until`` / ``mute_reason`` (set again by mute helpers).
    """
    when = now or datetime.now(UTC)
    finding.status = new_status
    if new_status == FindingStatus.RESOLVED:
        finding.resolved_at = when
    else:
        finding.resolved_at = None
    if new_status != FindingStatus.MUTED:
        finding.muted_until = None
        finding.mute_reason = None


def list_exceptions(db: Session, finding: Finding) -> list[dict]:
    rows = db.scalars(
        select(Exception_)
        .where(Exception_.finding_id == finding.id, Exception_.org_id == finding.org_id)
        .order_by(Exception_.created_at.desc())
    ).all()
    return [
        {
            "id": row.id,
            "reason": row.reason,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "created_by": _operator_out(db, row.created_by_operator_id),
        }
        for row in rows
    ]


def create_finding_exception(
    db: Session,
    *,
    finding: Finding,
    reason: str,
    created_by_operator_id: uuid.UUID,
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> Exception_:
    cleaned = reason.strip()
    if not cleaned:
        raise FindingInvestigationError("reason is required")
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    exception = Exception_(
        id=uuid.uuid4(),
        org_id=finding.org_id,
        finding_id=finding.id,
        reason=cleaned,
        created_by_operator_id=created_by_operator_id,
        expires_at=expires_at,
    )
    db.add(exception)
    apply_status_transition(finding, FindingStatus.EXCEPTION, now=now)
    return exception
