# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator notification preferences.

Any authenticated role may read/update their own prefs. They gate both
personal channels: the in-app inbox (`/notifications`) and email. Distinct from
finding mute and org outbound webhooks.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.notifications.email import email_delivery_configured
from kestrel.notifications.preferences import (
    NotificationPreferencesError,
    get_preferences_dict,
    update_preferences,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db

router = APIRouter(prefix="/notification-preferences", tags=["notification-preferences"])


class NotificationPreferencesOut(BaseModel):
    id: str
    operator_id: str
    email_enabled: bool
    in_app_enabled: bool
    findings_enabled: bool
    webhook_failures_enabled: bool
    min_severity: str
    muted_events: list[str]
    # Deployment-wide, not a preference: whether SMTP is configured, so the
    # email channel actually sends. Without it, email_enabled has no effect.
    email_configured: bool
    created_at: str | None = None
    updated_at: str | None = None


class NotificationPreferencesPatch(BaseModel):
    email_enabled: bool | None = None
    in_app_enabled: bool | None = None
    findings_enabled: bool | None = None
    webhook_failures_enabled: bool | None = None
    min_severity: str | None = Field(default=None, max_length=32)
    muted_events: list[str] | None = None


def _out(data: dict, *, email_configured: bool) -> NotificationPreferencesOut:
    return NotificationPreferencesOut(
        id=str(data["id"]),
        operator_id=str(data["operator_id"]),
        email_enabled=bool(data["email_enabled"]),
        in_app_enabled=bool(data["in_app_enabled"]),
        findings_enabled=bool(data["findings_enabled"]),
        webhook_failures_enabled=bool(data["webhook_failures_enabled"]),
        min_severity=str(data["min_severity"]),
        muted_events=list(data.get("muted_events") or []),
        email_configured=email_configured,
        created_at=data.get("created_at"),
        updated_at=data.get("updated_at"),
    )


@router.get("")
def get_notification_preferences(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> NotificationPreferencesOut:
    data = get_preferences_dict(db, org_id=org.id, operator_id=operator.id)
    db.commit()
    return _out(data, email_configured=email_delivery_configured(db, org.id))


@router.patch("")
def patch_notification_preferences(
    body: NotificationPreferencesPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> NotificationPreferencesOut:
    try:
        row = update_preferences(
            db,
            org_id=org.id,
            operator_id=operator.id,
            email_enabled=body.email_enabled,
            in_app_enabled=body.in_app_enabled,
            findings_enabled=body.findings_enabled,
            webhook_failures_enabled=body.webhook_failures_enabled,
            min_severity=body.min_severity,
            muted_events=body.muted_events,
        )
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=operator.id,
            action="operator.notification_preferences_updated",
            target_type="operator_notification_preferences",
            target_id=row.id,
            context={
                "email_enabled": row.email_enabled,
                "in_app_enabled": row.in_app_enabled,
                "findings_enabled": row.findings_enabled,
                "webhook_failures_enabled": row.webhook_failures_enabled,
                "min_severity": row.min_severity,
                "muted_events": list(row.muted_events or []),
            },
        )
        db.commit()
        data = get_preferences_dict(db, org_id=org.id, operator_id=operator.id)
    except NotificationPreferencesError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _out(data, email_configured=email_delivery_configured(db, org.id))
