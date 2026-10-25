# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator notification preferences.

Stores channel mutes and finding severity thresholds for the calling
operator. Distinct from finding mute and org webhook endpoints. Both
personal channels gate on ``should_notify``: ``channel=in_app`` for inbox rows
and ``channel=email`` for email (sent only when SMTP is configured).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.notification_prefs import OperatorNotificationPreferences
from kestrel.db.models.policy import Severity
from kestrel.db.models.webhook import SUPPORTED_WEBHOOK_EVENTS

Channel = Literal["email", "in_app"]
NotifyKind = Literal["finding", "webhook_failure"]

SEVERITY_RANK = {
    Severity.LOW.value: 0,
    Severity.MEDIUM.value: 1,
    Severity.HIGH.value: 2,
    Severity.CRITICAL.value: 3,
}

DEFAULT_MIN_SEVERITY = Severity.LOW.value
ALLOWED_MUTED_EVENTS = frozenset(SUPPORTED_WEBHOOK_EVENTS)


class NotificationPreferencesError(ValueError):
    """Invalid preference payload."""


def _serialize(row: OperatorNotificationPreferences) -> dict[str, Any]:
    return {
        "id": row.id,
        "operator_id": row.operator_id,
        "email_enabled": row.email_enabled,
        "in_app_enabled": row.in_app_enabled,
        "findings_enabled": row.findings_enabled,
        "webhook_failures_enabled": row.webhook_failures_enabled,
        "min_severity": row.min_severity,
        "muted_events": list(row.muted_events or []),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _normalize_min_severity(raw: str | None) -> str:
    if raw is None:
        return DEFAULT_MIN_SEVERITY
    if not isinstance(raw, str):
        raise NotificationPreferencesError("min_severity must be a string")
    value = raw.strip().lower()
    if value not in SEVERITY_RANK:
        raise NotificationPreferencesError(f"min_severity must be one of: {', '.join(SEVERITY_RANK)}")
    return value


def _normalize_muted_events(raw: list[Any] | None) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise NotificationPreferencesError("muted_events must be a list")
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise NotificationPreferencesError("muted_events entries must be strings")
        event = item.strip()
        if not event:
            continue
        if event not in ALLOWED_MUTED_EVENTS:
            raise NotificationPreferencesError(
                f"unsupported muted event {event!r}; supported: {', '.join(sorted(ALLOWED_MUTED_EVENTS))}"
            )
        if event not in seen:
            seen.add(event)
            out.append(event)
    return out


def _normalize_bool(raw: Any, field: str) -> bool:
    if not isinstance(raw, bool):
        raise NotificationPreferencesError(f"{field} must be a boolean")
    return raw


def get_or_create_preferences(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
) -> OperatorNotificationPreferences:
    """Return the operator's prefs row, creating defaults on first access."""
    row = db.scalars(
        select(OperatorNotificationPreferences).where(
            OperatorNotificationPreferences.org_id == org_id,
            OperatorNotificationPreferences.operator_id == operator_id,
        )
    ).first()
    if row is not None:
        return row

    row = OperatorNotificationPreferences(
        id=uuid.uuid4(),
        org_id=org_id,
        operator_id=operator_id,
        email_enabled=True,
        in_app_enabled=True,
        findings_enabled=True,
        webhook_failures_enabled=True,
        min_severity=DEFAULT_MIN_SEVERITY,
        muted_events=[],
    )
    db.add(row)
    db.flush()
    return row


def get_preferences_dict(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
) -> dict[str, Any]:
    return _serialize(get_or_create_preferences(db, org_id=org_id, operator_id=operator_id))


def update_preferences(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    email_enabled: bool | None = None,
    in_app_enabled: bool | None = None,
    findings_enabled: bool | None = None,
    webhook_failures_enabled: bool | None = None,
    min_severity: str | None = None,
    muted_events: list[Any] | None = None,
) -> OperatorNotificationPreferences:
    """Patch prefs for the calling operator. At least one field required."""
    if (
        email_enabled is None
        and in_app_enabled is None
        and findings_enabled is None
        and webhook_failures_enabled is None
        and min_severity is None
        and muted_events is None
    ):
        raise NotificationPreferencesError("no fields to update")

    row = get_or_create_preferences(db, org_id=org_id, operator_id=operator_id)

    if email_enabled is not None:
        row.email_enabled = _normalize_bool(email_enabled, "email_enabled")
    if in_app_enabled is not None:
        row.in_app_enabled = _normalize_bool(in_app_enabled, "in_app_enabled")
    if findings_enabled is not None:
        row.findings_enabled = _normalize_bool(findings_enabled, "findings_enabled")
    if webhook_failures_enabled is not None:
        row.webhook_failures_enabled = _normalize_bool(webhook_failures_enabled, "webhook_failures_enabled")
    if min_severity is not None:
        row.min_severity = _normalize_min_severity(min_severity)
    if muted_events is not None:
        row.muted_events = _normalize_muted_events(muted_events)

    db.flush()
    return row


def should_notify(
    prefs: OperatorNotificationPreferences | dict[str, Any],
    *,
    channel: Channel,
    kind: NotifyKind,
    severity: str | None = None,
    event_type: str | None = None,
) -> bool:
    """Whether a personal notification should be delivered on ``channel``.

    Org outbound webhooks are unaffected — this gates personal email/in-app
    delivery only. Finding mute is a separate finding lifecycle
    control and is not consulted here.
    """
    data = _serialize(prefs) if isinstance(prefs, OperatorNotificationPreferences) else prefs

    if channel == "email" and not data.get("email_enabled", True):
        return False
    if channel == "in_app" and not data.get("in_app_enabled", True):
        return False

    if kind == "webhook_failure":
        return bool(data.get("webhook_failures_enabled", True))

    # kind == "finding"
    if not data.get("findings_enabled", True):
        return False

    muted = set(data.get("muted_events") or [])
    if event_type and event_type in muted:
        return False

    if severity is not None:
        sev = severity.strip().lower()
        if sev not in SEVERITY_RANK:
            return False
        min_sev = str(data.get("min_severity") or DEFAULT_MIN_SEVERITY).strip().lower()
        if min_sev not in SEVERITY_RANK:
            min_sev = DEFAULT_MIN_SEVERITY
        if SEVERITY_RANK[sev] < SEVERITY_RANK[min_sev]:
            return False

    return True
