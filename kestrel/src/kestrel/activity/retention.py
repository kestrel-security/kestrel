# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Retention and volume caps for activity_events.

Defaults are deliberately conservative for a self-hosted deployment: 90-day
window and 50k rows per application instance. Documented in
``docs/domain-model.md``. No UEBA / ML scoring.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from kestrel.db.models.activity_event import ActivityEvent

DEFAULT_RETENTION_DAYS = 90
DEFAULT_MAX_EVENTS_PER_INSTANCE = 50_000


def prune_activity_events(
    session: Session,
    *,
    org_id: uuid.UUID | None = None,
    application_instance_id: uuid.UUID | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    max_per_instance: int = DEFAULT_MAX_EVENTS_PER_INSTANCE,
    now: datetime | None = None,
) -> dict[str, int]:
    """Delete aged-out rows, then trim each instance to ``max_per_instance``.

    Returns counts of rows removed by age and by volume cap.
    """
    if retention_days < 1:
        raise ValueError("retention_days must be >= 1")
    if max_per_instance < 1:
        raise ValueError("max_per_instance must be >= 1")

    clock = now or datetime.now(UTC)
    cutoff = clock - timedelta(days=retention_days)

    age_filters = [ActivityEvent.occurred_at < cutoff]
    if org_id is not None:
        age_filters.append(ActivityEvent.org_id == org_id)
    if application_instance_id is not None:
        age_filters.append(ActivityEvent.application_instance_id == application_instance_id)

    age_result = session.execute(delete(ActivityEvent).where(*age_filters))
    deleted_by_age = int(getattr(age_result, "rowcount", 0) or 0)

    instance_q = select(ActivityEvent.application_instance_id).distinct()
    if org_id is not None:
        instance_q = instance_q.where(ActivityEvent.org_id == org_id)
    if application_instance_id is not None:
        instance_q = instance_q.where(ActivityEvent.application_instance_id == application_instance_id)

    deleted_by_cap = 0
    for (instance_id,) in session.execute(instance_q).all():
        count = (
            session.scalar(
                select(func.count()).select_from(ActivityEvent).where(ActivityEvent.application_instance_id == instance_id)
            )
            or 0
        )
        excess = count - max_per_instance
        if excess <= 0:
            continue
        # Drop oldest first.
        oldest_ids = session.scalars(
            select(ActivityEvent.id)
            .where(ActivityEvent.application_instance_id == instance_id)
            .order_by(ActivityEvent.occurred_at.asc(), ActivityEvent.id.asc())
            .limit(excess)
        ).all()
        if oldest_ids:
            cap_result = session.execute(delete(ActivityEvent).where(ActivityEvent.id.in_(oldest_ids)))
            deleted_by_cap += int(getattr(cap_result, "rowcount", 0) or 0)

    return {"deleted_by_age": deleted_by_age, "deleted_by_cap": deleted_by_cap}
