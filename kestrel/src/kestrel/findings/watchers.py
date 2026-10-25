# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding watch subscribe/unsubscribe.

Per-operator opt-in for in-app updates on a specific finding. Distinct from
assignment and mute. Delivery uses inbox dispatch.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.findings.listing import finding_summary


class FindingWatcherError(ValueError):
    """Invalid watch operation."""


def is_watching(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    finding_id: uuid.UUID,
) -> bool:
    row = db.scalars(
        select(FindingWatcher).where(
            FindingWatcher.org_id == org_id,
            FindingWatcher.operator_id == operator_id,
            FindingWatcher.finding_id == finding_id,
        )
    ).first()
    return row is not None


def watcher_operator_ids(
    db: Session,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
) -> list[uuid.UUID]:
    return list(
        db.scalars(
            select(FindingWatcher.operator_id).where(
                FindingWatcher.org_id == org_id,
                FindingWatcher.finding_id == finding_id,
            )
        ).all()
    )


def watch_finding(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    finding: Finding,
) -> FindingWatcher:
    """Subscribe the operator to ``finding``. Idempotent."""
    if finding.org_id != org_id:
        raise FindingWatcherError("finding not found")

    existing = db.scalars(
        select(FindingWatcher).where(
            FindingWatcher.org_id == org_id,
            FindingWatcher.operator_id == operator_id,
            FindingWatcher.finding_id == finding.id,
        )
    ).first()
    if existing is not None:
        return existing

    row = FindingWatcher(
        id=uuid.uuid4(),
        org_id=org_id,
        operator_id=operator_id,
        finding_id=finding.id,
    )
    db.add(row)
    db.flush()
    return row


def unwatch_finding(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    finding: Finding,
) -> bool:
    """Remove the operator's watch. Returns True if a row was deleted."""
    if finding.org_id != org_id:
        raise FindingWatcherError("finding not found")

    row = db.scalars(
        select(FindingWatcher).where(
            FindingWatcher.org_id == org_id,
            FindingWatcher.operator_id == operator_id,
            FindingWatcher.finding_id == finding.id,
        )
    ).first()
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True


def list_watched_findings(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Newest watches first; each item is a finding summary + watching=true."""
    cap = max(1, min(limit, 200))
    watches = list(
        db.scalars(
            select(FindingWatcher)
            .where(
                FindingWatcher.org_id == org_id,
                FindingWatcher.operator_id == operator_id,
            )
            .order_by(FindingWatcher.created_at.desc())
            .limit(cap)
        ).all()
    )
    out: list[dict[str, Any]] = []
    for watch in watches:
        finding = db.get(Finding, watch.finding_id)
        if finding is None or finding.org_id != org_id:
            continue
        summary = finding_summary(db, finding)
        summary["watching"] = True
        summary["watched_at"] = watch.created_at.isoformat() if watch.created_at else None
        out.append(summary)
    return out
