# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Daily posture trend capture.

Forward-only UTC day snapshots of scorecard factor counts + open findings by
severity. No historical backfill.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Severity
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.reports.posture_scorecard import posture_scorecard_report


def _utc_today(now: datetime | None = None) -> date:
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)
    return clock.astimezone(UTC).date()


def _open_by_severity(db: Session, org_id: uuid.UUID) -> dict[str, int]:
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    ).all()
    out = {s.value: 0 for s in Severity}
    for severity, count in rows:
        key = severity.value if isinstance(severity, Severity) else str(severity)
        out[key] = int(count)
    return out


def capture_posture_snapshot(
    db: Session,
    org_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> PostureTrendSnapshot:
    """Upsert today's posture snapshot for ``org_id`` (idempotent per UTC day)."""
    today = _utc_today(now)
    scorecard = posture_scorecard_report(db, org_id)
    open_by_sev = _open_by_severity(db, org_id)
    factor_counts = {f["key"]: int(f["count"]) for f in scorecard["factors"]}
    attention = int(scorecard["attention_count"])

    existing = db.scalars(
        select(PostureTrendSnapshot).where(
            PostureTrendSnapshot.org_id == org_id,
            PostureTrendSnapshot.snapshot_date == today,
        )
    ).one_or_none()

    if existing is None:
        row = PostureTrendSnapshot(
            id=uuid.uuid4(),
            org_id=org_id,
            snapshot_date=today,
            open_by_severity=open_by_sev,
            factor_counts=factor_counts,
            attention_count=attention,
        )
        db.add(row)
        db.flush()
        return row

    existing.open_by_severity = open_by_sev
    existing.factor_counts = factor_counts
    existing.attention_count = attention
    db.flush()
    return existing
