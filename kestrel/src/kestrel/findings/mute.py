# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding mute / snooze lifecycle.

Temporary deferral distinct from permanent suppress and accepted-risk
exceptions. Mute always requires an expiry (``muted_until``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.operator import Operator
from kestrel.findings.investigation.status import FindingInvestigationError, apply_status_transition

DEFAULT_WITHIN_DAYS = 14
QUEUE_ITEMS_LIMIT = 50
# Hard cap so mute cannot become indefinite suppress-by-another-name.
MAX_MUTE_DAYS = 90
PRESET_DURATIONS = frozenset({1, 7, 30})


def mute_finding(
    finding: Finding,
    *,
    muted_until: datetime,
    reason: str | None = None,
    now: datetime | None = None,
) -> None:
    """Set status=muted with a required future expiry."""
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)
    until = muted_until
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    if until <= clock:
        raise FindingInvestigationError("muted_until must be in the future")
    max_until = clock + timedelta(days=MAX_MUTE_DAYS)
    if until > max_until:
        raise FindingInvestigationError(f"muted_until must be within {MAX_MUTE_DAYS} days")

    cleaned = (reason or "").strip() or None
    apply_status_transition(finding, FindingStatus.MUTED, now=clock)
    finding.muted_until = until
    finding.mute_reason = cleaned


def mute_finding_for_days(
    finding: Finding,
    *,
    days: int,
    reason: str | None = None,
    now: datetime | None = None,
) -> None:
    """Convenience mute using a duration preset (1 / 7 / 30 days)."""
    if days not in PRESET_DURATIONS and not (1 <= days <= MAX_MUTE_DAYS):
        raise FindingInvestigationError(f"days must be one of {sorted(PRESET_DURATIONS)} or 1–{MAX_MUTE_DAYS}")
    clock = now or datetime.now(UTC)
    mute_finding(
        finding,
        muted_until=clock + timedelta(days=days),
        reason=reason,
        now=clock,
    )


def unmute_finding(finding: Finding, *, now: datetime | None = None) -> None:
    """Return a muted finding to open (clears mute fields via transition)."""
    if finding.status != FindingStatus.MUTED:
        raise FindingInvestigationError("finding is not muted")
    apply_status_transition(finding, FindingStatus.OPEN, now=now)


def _operator_out(db: Session, operator_id: uuid.UUID | None) -> dict | None:
    if operator_id is None:
        return None
    operator = db.get(Operator, operator_id)
    if operator is None:
        return None
    return {"id": operator.id, "email": operator.email, "display_name": operator.display_name}


def expiring_mutes(
    db: Session,
    org_id: uuid.UUID,
    *,
    within_days: int = DEFAULT_WITHIN_DAYS,
    now: datetime | None = None,
    limit: int = QUEUE_ITEMS_LIMIT,
) -> dict[str, Any]:
    """Org-scoped mute expiry queue (distinct from exception expiry)."""
    if within_days < 0:
        raise ValueError("within_days must be >= 0")

    clock = now or datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)
    horizon = clock + timedelta(days=within_days)

    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.MUTED,
                Finding.muted_until.is_not(None),
            )
        ).all()
    )

    items: list[dict[str, Any]] = []
    for finding in findings:
        until = finding.muted_until
        if until is None:
            continue
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        if until <= clock:
            state = "expired"
        elif until <= horizon:
            state = "expiring_soon"
        else:
            continue
        items.append(
            {
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "reason": finding.mute_reason,
                "muted_until": until.isoformat(),
                "state": state,
                "detail_path": f"/findings/{finding.id}",
            }
        )

    items.sort(key=lambda row: (0 if row["state"] == "expired" else 1, row["muted_until"]))
    expired_count = sum(1 for row in items if row["state"] == "expired")
    expiring_soon_count = sum(1 for row in items if row["state"] == "expiring_soon")
    capped = items[: max(limit, 0)]
    return {
        "within_days": within_days,
        "as_of": clock.isoformat(),
        "expired_count": expired_count,
        "expiring_soon_count": expiring_soon_count,
        "truncated": len(items) > len(capped),
        "items": capped,
    }
