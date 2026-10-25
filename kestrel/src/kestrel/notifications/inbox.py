# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator in-app notification inbox queries.

Every function is scoped to one ``(org_id, operator_id)``: an operator can only
ever see or mark their own rows. Served by ``GET /notifications`` and friends.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from kestrel.db.models.in_app_notification import OperatorInAppNotification


class InboxError(LookupError):
    """The notification does not exist for this operator."""


def _now() -> datetime:
    return datetime.now(UTC)


def serialize_notification(row: OperatorInAppNotification) -> dict[str, Any]:
    payload = dict(row.payload or {})
    detail_path = None
    if row.kind == "webhook_failure":
        if isinstance(payload.get("detail_path"), str) and payload["detail_path"]:
            detail_path = payload["detail_path"]
        elif isinstance(payload.get("endpoint"), dict):
            ep_path = payload["endpoint"].get("detail_path")
            if isinstance(ep_path, str) and ep_path:
                detail_path = ep_path
    elif row.finding_id is not None:
        detail_path = f"/findings/{row.finding_id}"
    return {
        "id": row.id,
        "operator_id": row.operator_id,
        "kind": row.kind,
        "event_type": row.event_type,
        "title": row.title,
        "body": row.body,
        "finding_id": row.finding_id,
        "severity": row.severity,
        "payload": payload,
        "read_at": row.read_at.isoformat() if row.read_at else None,
        "is_read": row.read_at is not None,
        "detail_path": detail_path,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def unread_count(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
) -> int:
    count = db.scalar(
        select(func.count())
        .select_from(OperatorInAppNotification)
        .where(
            OperatorInAppNotification.org_id == org_id,
            OperatorInAppNotification.operator_id == operator_id,
            OperatorInAppNotification.read_at.is_(None),
        )
    )
    return int(count or 0)


def notifications_query(
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    unread_only: bool = False,
) -> Select[tuple[OperatorInAppNotification]]:
    """Unordered select of the operator's inbox rows; callers add ordering
    and pagination (the API applies keyset pagination on ``created_at``)."""
    stmt = select(OperatorInAppNotification).where(
        OperatorInAppNotification.org_id == org_id,
        OperatorInAppNotification.operator_id == operator_id,
    )
    if unread_only:
        stmt = stmt.where(OperatorInAppNotification.read_at.is_(None))
    return stmt


def get_notification(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    notification_id: uuid.UUID,
) -> OperatorInAppNotification:
    row = db.scalar(
        select(OperatorInAppNotification).where(
            OperatorInAppNotification.org_id == org_id,
            OperatorInAppNotification.operator_id == operator_id,
            OperatorInAppNotification.id == notification_id,
        )
    )
    if row is None:
        raise InboxError("notification not found")
    return row


def mark_read(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    notification_id: uuid.UUID,
) -> OperatorInAppNotification:
    """Idempotent: an already-read row keeps its original ``read_at``."""
    row = get_notification(db, org_id=org_id, operator_id=operator_id, notification_id=notification_id)
    if row.read_at is None:
        row.read_at = _now()
        db.flush()
    return row


def mark_all_read(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
) -> int:
    now = _now()
    unread = list(
        db.scalars(
            select(OperatorInAppNotification).where(
                OperatorInAppNotification.org_id == org_id,
                OperatorInAppNotification.operator_id == operator_id,
                OperatorInAppNotification.read_at.is_(None),
            )
        ).all()
    )
    for row in unread:
        row.read_at = now
    if unread:
        db.flush()
    return len(unread)
