# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identity timeline: chronological grants / attribute / finding activity.

Merges sync `events` for the identity, synthesized grant / OAuth grant
signals (relationship rows are not Event-tracked in v1 — see upsert.py),
and finding open/resolve timestamps for the Identity Explorer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.access import Grant, Role
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant
from kestrel.db.models.resource import Resource

TIMELINE_LIMIT_DEFAULT = 50
TIMELINE_LIMIT_MAX = 200

_IDENTITY_FIELD_LABELS = {
    "identity_type": "identity type",
    "email": "email",
    "display_name": "display name",
    "is_disabled": "disabled",
    "mfa_enabled": "MFA",
    "is_external": "external",
}


def clamp_timeline_limit(raw: int | None) -> int:
    if raw is None:
        return TIMELINE_LIMIT_DEFAULT
    return max(1, min(int(raw), TIMELINE_LIMIT_MAX))


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _field_change_summary(field_changes: list | None) -> str:
    if not field_changes:
        return "Identity attributes updated"
    parts: list[str] = []
    for change in field_changes:
        if not isinstance(change, dict):
            continue
        field = str(change.get("field") or "")
        label = _IDENTITY_FIELD_LABELS.get(field, field or "field")
        old = change.get("old")
        new = change.get("new")
        parts.append(f"{label}: {old!r} → {new!r}")
    if not parts:
        return "Identity attributes updated"
    if len(parts) == 1:
        return f"Updated {parts[0]}"
    return f"Updated {len(parts)} attributes ({', '.join(parts[:3])}{'…' if len(parts) > 3 else ''})"


def _grant_label(db: Session, grant: Grant) -> str:
    if grant.resource_id is not None:
        resource = db.get(Resource, grant.resource_id)
        if resource is not None and resource.org_id == grant.org_id:
            return resource.name
    if grant.role_id is not None:
        role = db.get(Role, grant.role_id)
        if role is not None and role.org_id == grant.org_id:
            return role.name
    if grant.permission_level:
        return grant.permission_level
    return "Grant"


def _oauth_app_name(db: Session, grant: OAuthGrant) -> str:
    app = db.get(OAuthApplication, grant.oauth_application_id)
    if app is not None and app.org_id == grant.org_id:
        return app.name
    return f"OAuth app {str(grant.oauth_application_id)[:8]}…"


def _event_items(db: Session, *, org_id: uuid.UUID, identity_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Event)
        .where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.entity_id == identity_id,
            Event.change_type != ChangeType.UNCHANGED,
        )
        .order_by(Event.detected_at.desc())
        .limit(TIMELINE_LIMIT_MAX)
    ).all()

    items: list[dict[str, Any]] = []
    for row in rows:
        change = row.change_type.value if isinstance(row.change_type, ChangeType) else str(row.change_type)
        if change == ChangeType.CREATED.value:
            summary = "Identity first seen in sync"
            action = "identity.created"
        elif change == ChangeType.DELETED.value:
            summary = "Identity removed from sync"
            action = "identity.deleted"
        else:
            summary = _field_change_summary(row.field_changes if isinstance(row.field_changes, list) else None)
            action = "identity.updated"
        items.append(
            {
                "at": _iso(row.detected_at),
                "kind": "sync",
                "action": action,
                "summary": summary,
                "href": None,
                "context": {
                    "change_type": change,
                    "connector_run_id": str(row.connector_run_id),
                    "field_changes": row.field_changes if isinstance(row.field_changes, list) else [],
                },
            }
        )
    return items


def _grant_items(db: Session, *, org_id: uuid.UUID, identity_id: uuid.UUID) -> list[dict[str, Any]]:
    grants = db.scalars(
        select(Grant).where(Grant.org_id == org_id, Grant.identity_id == identity_id).limit(TIMELINE_LIMIT_MAX)
    ).all()
    items: list[dict[str, Any]] = []
    for grant in grants:
        label = _grant_label(db, grant)
        privileged = False
        if grant.role_id is not None:
            role = db.get(Role, grant.role_id)
            if role is not None and role.org_id == org_id:
                privileged = bool(role.is_privileged)
        items.append(
            {
                "at": _iso(grant.first_seen_at),
                "kind": "grant",
                "action": "grant.created",
                "summary": f"Grant first seen: {label}" + (" (privileged)" if privileged else ""),
                "href": None,
                "context": {
                    "grant_id": str(grant.id),
                    "granted_via": grant.granted_via.value,
                    "permission_level": grant.permission_level,
                    "role_id": str(grant.role_id) if grant.role_id else None,
                    "resource_id": str(grant.resource_id) if grant.resource_id else None,
                    "role_is_privileged": privileged,
                    "source_connector_run_id": str(grant.source_connector_run_id),
                    "synthesized": True,
                },
            }
        )
    return items


def _oauth_grant_items(db: Session, *, org_id: uuid.UUID, identity_id: uuid.UUID) -> list[dict[str, Any]]:
    grants = db.scalars(
        select(OAuthGrant)
        .where(OAuthGrant.org_id == org_id, OAuthGrant.identity_id == identity_id)
        .limit(TIMELINE_LIMIT_MAX)
    ).all()
    items: list[dict[str, Any]] = []
    for grant in grants:
        name = _oauth_app_name(db, grant)
        items.append(
            {
                "at": _iso(grant.granted_at),
                "kind": "oauth_grant",
                "action": "oauth_grant.created",
                "summary": f"OAuth grant: {name}",
                "href": None,
                "context": {
                    "oauth_grant_id": str(grant.id),
                    "oauth_application_id": str(grant.oauth_application_id),
                    "oauth_application_name": name,
                    "last_used_at": _iso(grant.last_used_at),
                    "synthesized": True,
                },
            }
        )
    return items


def _finding_items(db: Session, *, org_id: uuid.UUID, identity_id: uuid.UUID) -> list[dict[str, Any]]:
    findings = db.scalars(
        select(Finding)
        .where(
            Finding.org_id == org_id,
            Finding.subject_type == FindingSubjectType.IDENTITY,
            Finding.subject_id == identity_id,
        )
        .limit(TIMELINE_LIMIT_MAX)
    ).all()
    items: list[dict[str, Any]] = []
    for finding in findings:
        href = f"/findings/{finding.id}"
        items.append(
            {
                "at": _iso(finding.first_seen_at),
                "kind": "finding",
                "action": "finding.opened",
                "summary": f"Finding opened: {finding.title}",
                "href": href,
                "context": {
                    "finding_id": str(finding.id),
                    "severity": finding.severity.value,
                    "status": FindingStatus.OPEN.value,
                },
            }
        )
        if finding.resolved_at is not None:
            items.append(
                {
                    "at": _iso(finding.resolved_at),
                    "kind": "finding",
                    "action": "finding.resolved",
                    "summary": f"Finding resolved: {finding.title}",
                    "href": href,
                    "context": {
                        "finding_id": str(finding.id),
                        "severity": finding.severity.value,
                        "status": FindingStatus.RESOLVED.value,
                    },
                }
            )
    return items


def identity_timeline(
    db: Session,
    *,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Newest-first merged timeline for one identity.

    Grant / OAuth rows are synthesized from first-seen / granted_at because
    sync change detection does not emit `events` for relationship objects yet.
    """
    capped = clamp_timeline_limit(limit)
    items = (
        _event_items(db, org_id=org_id, identity_id=identity_id)
        + _grant_items(db, org_id=org_id, identity_id=identity_id)
        + _oauth_grant_items(db, org_id=org_id, identity_id=identity_id)
        + _finding_items(db, org_id=org_id, identity_id=identity_id)
    )
    items = [item for item in items if item.get("at")]
    items.sort(key=lambda e: e["at"], reverse=True)
    return items[:capped]
