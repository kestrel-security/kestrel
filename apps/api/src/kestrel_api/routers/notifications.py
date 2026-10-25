# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The calling operator's in-app notification inbox.

Rows are written by ``kestrel.notifications.dispatch`` (finding lifecycle for
org-wide prefs and watched findings, webhook delivery failures). Every route is
scoped to the authenticated operator and their org: there is no way to read or
mark another operator's notifications, so any role may use it.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.notifications.inbox import (
    InboxError,
    mark_all_read,
    mark_read,
    notifications_query,
    serialize_notification,
    unread_count,
)
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db
from kestrel_api.pagination import apply_keyset, build_page, normalize_limit

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
def list_notifications(
    unread_only: bool = Query(default=False, description="Only notifications not yet marked read."),
    limit: int | None = None,
    cursor: str | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """The caller's notifications, newest first.

    Ordered `created_at DESC, id DESC`. Cursor-paginated `{items, next_cursor}`,
    plus `unread_count` so a client can render a badge from the same request."""
    page_limit = normalize_limit(limit)
    stmt = apply_keyset(
        notifications_query(org_id=org.id, operator_id=operator.id, unread_only=unread_only),
        sort_column=OperatorInAppNotification.created_at,
        id_column=OperatorInAppNotification.id,
        cursor=cursor,
        limit=page_limit,
    )
    rows = list(db.scalars(stmt).all())
    page = build_page(rows, limit=page_limit, sort_attr="created_at", serializer=serialize_notification)
    page["unread_count"] = unread_count(db, org_id=org.id, operator_id=operator.id)
    return page


@router.get("/unread-count")
def get_unread_count(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """How many of the caller's notifications are unread."""
    return {"unread_count": unread_count(db, org_id=org.id, operator_id=operator.id)}


@router.post("/read-all")
def read_all_notifications(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Mark every unread notification read. Returns how many changed."""
    updated = mark_all_read(db, org_id=org.id, operator_id=operator.id)
    db.commit()
    return {"updated": updated, "unread_count": 0}


@router.post("/{notification_id}/read")
def read_notification(
    notification_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Mark one notification read. Idempotent; 404 for another operator's row."""
    try:
        row = mark_read(db, org_id=org.id, operator_id=operator.id, notification_id=notification_id)
    except InboxError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return serialize_notification(row)
