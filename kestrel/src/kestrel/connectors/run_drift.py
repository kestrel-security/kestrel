# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector sync-run drift / change diff.

Reads per-run ``events`` written by the sync pipeline (entity create/update/
delete with optional ``field_changes``), covering both entity attributes and
relationship churn (grants, group memberships, OAuth grants).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from kestrel.changes.labels import entity_label
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus
from kestrel.db.models.event import ChangeType, Event

DRIFT_LIMIT_DEFAULT = 50
DRIFT_LIMIT_MAX = 200


def clamp_drift_limit(raw: int | None) -> int:
    if raw is None:
        return DRIFT_LIMIT_DEFAULT
    return max(1, min(int(raw), DRIFT_LIMIT_MAX))


def _empty_summary() -> dict[str, Any]:
    return {
        "total": 0,
        "by_change_type": {"created": 0, "updated": 0, "deleted": 0},
        "by_entity_type": {},
    }


def run_change_summary(db: Session, org_id: uuid.UUID, run_id: uuid.UUID) -> dict[str, Any]:
    """Aggregate Event counts for a connector run (excludes unchanged)."""
    rows = db.execute(
        select(Event.change_type, Event.entity_type, func.count())
        .where(
            Event.org_id == org_id,
            Event.connector_run_id == run_id,
            Event.change_type != ChangeType.UNCHANGED,
        )
        .group_by(Event.change_type, Event.entity_type)
    ).all()

    summary = _empty_summary()
    by_change = summary["by_change_type"]
    by_entity: dict[str, int] = {}
    total = 0
    for change_type, entity_type, count in rows:
        n = int(count)
        total += n
        key = change_type.value if hasattr(change_type, "value") else str(change_type)
        if key in by_change:
            by_change[key] += n
        by_entity[str(entity_type)] = by_entity.get(str(entity_type), 0) + n
    summary["total"] = total
    summary["by_entity_type"] = dict(sorted(by_entity.items()))
    return summary


def previous_successful_run(
    db: Session,
    org_id: uuid.UUID,
    *,
    connector_instance_id: uuid.UUID,
    before_run: ConnectorRun,
) -> ConnectorRun | None:
    """Prior successful run for the same instance (for compare context)."""
    stmt = (
        select(ConnectorRun)
        .where(
            ConnectorRun.org_id == org_id,
            ConnectorRun.connector_instance_id == connector_instance_id,
            ConnectorRun.status == ConnectorRunStatus.SUCCESS,
            ConnectorRun.id != before_run.id,
        )
        .order_by(ConnectorRun.finished_at.desc().nullslast(), ConnectorRun.started_at.desc())
        .limit(20)
    )
    candidates = list(db.scalars(stmt).all())
    if before_run.started_at is None:
        return candidates[0] if candidates else None
    for run in candidates:
        if run.started_at is not None and run.started_at < before_run.started_at:
            return run
        if run.finished_at is not None and run.finished_at < before_run.started_at:
            return run
    return None


def _changes_stmt(
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    change_type: str | None,
    entity_type: str | None,
) -> Select[tuple[Event]]:
    stmt = select(Event).where(
        Event.org_id == org_id,
        Event.connector_run_id == run_id,
        Event.change_type != ChangeType.UNCHANGED,
    )
    if change_type:
        try:
            ct = ChangeType(change_type)
        except ValueError as exc:
            raise ValueError(f"invalid change_type: {change_type}") from exc
        if ct == ChangeType.UNCHANGED:
            raise ValueError("change_type=unchanged is not listed in drift")
        stmt = stmt.where(Event.change_type == ct)
    if entity_type:
        stmt = stmt.where(Event.entity_type == entity_type)
    return stmt.order_by(Event.detected_at.desc(), Event.id.desc())


def list_run_changes(
    db: Session,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    change_type: str | None = None,
    entity_type: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any] | None:
    """Paginated drift rows for a run, or ``None`` if run missing / wrong tenant."""
    run = db.get(ConnectorRun, run_id)
    if run is None or run.org_id != org_id:
        return None

    lim = clamp_drift_limit(limit)
    off = max(0, int(offset))
    try:
        stmt = _changes_stmt(org_id, run_id, change_type=change_type, entity_type=entity_type)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    events = list(db.scalars(stmt.offset(off).limit(lim)).all())

    changes: list[dict[str, Any]] = []
    for event in events:
        label = entity_label(db, org_id, event.entity_type, event.entity_id)
        changes.append(
            {
                "id": event.id,
                "entity_type": event.entity_type,
                "entity_id": event.entity_id,
                "change_type": event.change_type.value,
                "field_changes": event.field_changes or [],
                "detected_at": event.detected_at.isoformat() if event.detected_at else None,
                "label": label["label"],
                "detail_path": label["detail_path"],
            }
        )

    summary = run_change_summary(db, org_id, run_id)
    prev = previous_successful_run(
        db,
        org_id,
        connector_instance_id=run.connector_instance_id,
        before_run=run,
    )
    previous: dict[str, Any] | None = None
    if prev is not None:
        previous = {
            "id": prev.id,
            "status": prev.status.value,
            "started_at": prev.started_at.isoformat() if prev.started_at else None,
            "finished_at": prev.finished_at.isoformat() if prev.finished_at else None,
            "detail_path": f"/connectors/runs/{prev.id}",
            "change_summary": run_change_summary(db, org_id, prev.id),
        }

    return {
        "run_id": run.id,
        "limit": lim,
        "offset": off,
        "total": int(total),
        "truncated": int(total) > off + len(changes),
        "change_summary": summary,
        "previous_successful_run": previous,
        "changes": changes,
        "filters": {
            "change_type": change_type,
            "entity_type": entity_type,
        },
    }
