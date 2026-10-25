# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Exception expiry review queue for SecOps.

Surfaces findings currently in `exception` status whose latest dated
exception is expired or expiring within a configurable window.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Exception_, Finding, FindingStatus
from kestrel.db.models.operator import Operator

DEFAULT_WITHIN_DAYS = 14
QUEUE_ITEMS_LIMIT = 50


def _operator_out(db: Session, operator_id: uuid.UUID | None) -> dict | None:
    if operator_id is None:
        return None
    operator = db.get(Operator, operator_id)
    if operator is None:
        return None
    return {"id": operator.id, "email": operator.email, "display_name": operator.display_name}


def expiring_exceptions(
    db: Session,
    org_id: uuid.UUID,
    *,
    within_days: int = DEFAULT_WITHIN_DAYS,
    now: datetime | None = None,
    limit: int = QUEUE_ITEMS_LIMIT,
) -> dict[str, Any]:
    """Org-scoped exception expiry queue.

    For each finding in ``exception`` status, uses the newest exception row
    that has ``expires_at`` set. Indefinite exceptions (null expiry) are
    omitted. Items are classified ``expired`` or ``expiring_soon``.
    """
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
                Finding.status == FindingStatus.EXCEPTION,
            )
        ).all()
    )
    if not findings:
        return {
            "within_days": within_days,
            "as_of": clock.isoformat(),
            "expired_count": 0,
            "expiring_soon_count": 0,
            "items": [],
        }

    finding_ids = [f.id for f in findings]
    rows = list(
        db.scalars(
            select(Exception_)
            .where(
                Exception_.org_id == org_id,
                Exception_.finding_id.in_(finding_ids),
                Exception_.expires_at.is_not(None),
            )
            .order_by(Exception_.created_at.desc())
        ).all()
    )

    latest_by_finding: dict[uuid.UUID, Exception_] = {}
    for row in rows:
        if row.finding_id is None:
            continue
        if row.finding_id not in latest_by_finding:
            latest_by_finding[row.finding_id] = row

    finding_by_id = {f.id: f for f in findings}
    items: list[dict[str, Any]] = []
    for finding_id, exc in latest_by_finding.items():
        finding = finding_by_id.get(finding_id)
        expires = exc.expires_at
        if finding is None or expires is None:
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= clock:
            state = "expired"
        elif expires <= horizon:
            state = "expiring_soon"
        else:
            continue
        items.append(
            {
                "exception_id": exc.id,
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "reason": exc.reason,
                "expires_at": expires.isoformat(),
                "state": state,
                "created_at": exc.created_at.isoformat() if exc.created_at else None,
                "created_by": _operator_out(db, exc.created_by_operator_id),
                "detail_path": f"/findings/{finding.id}",
            }
        )

    # Expired first, then soonest expiry.
    items.sort(key=lambda row: (0 if row["state"] == "expired" else 1, row["expires_at"]))
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
