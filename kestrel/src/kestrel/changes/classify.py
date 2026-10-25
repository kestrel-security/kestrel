# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Turns the raw sync diff into named change classes.

``events`` records *that* something changed; this records *what kind* of change
it was, which is what an operator actually triages: "someone became an admin"
rather than "grant 8f21… was created".

Classification is derived at read time rather than stored on the event. Rules
here improve as the model learns more about a provider (role privilege, scope
sensitivity), and deriving means those improvements apply to history instead of
requiring a backfill of rows classified by an older ruleset.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.changes.labels import entity_label
from kestrel.db.models.access import Grant, Group, GroupMembership, Role
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.setting import TenantSetting


class ChangeClass(str, enum.Enum):
    ADMIN_GRANTED = "admin_granted"
    ADMIN_REVOKED = "admin_revoked"
    PRIVILEGE_ESCALATED = "privilege_escalated"
    PRIVILEGE_REDUCED = "privilege_reduced"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    GROUP_MEMBER_ADDED = "group_member_added"
    GROUP_MEMBER_REMOVED = "group_member_removed"
    OAUTH_APP_INSTALLED = "oauth_app_installed"
    OAUTH_APP_REVOKED = "oauth_app_revoked"
    OAUTH_SCOPE_EXPANDED = "oauth_scope_expanded"
    EXTERNAL_SHARING_ENABLED = "external_sharing_enabled"
    MFA_DISABLED = "mfa_disabled"
    IDENTITY_DISABLED = "identity_disabled"
    IDENTITY_ADDED = "identity_added"
    IDENTITY_REMOVED = "identity_removed"
    CONFIG_DRIFT = "config_drift"
    OTHER = "other"


class Significance(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_SIGNIFICANCE_ORDER = {Significance.HIGH: 0, Significance.MEDIUM: 1, Significance.LOW: 2}

# Normalized across connectors by their normalizers (GitHub's admin/push/pull
# and Google's organizer/writer/reader both land here).
_PERMISSION_RANK = {"read": 0, "write": 1, "admin": 2}

# Setting categories where a change is posture-relevant rather than cosmetic.
_SENSITIVE_SETTING_CATEGORIES = frozenset({"security", "sharing", "access"})

# Values that mean "open to people outside the tenant".
_PERMISSIVE_VALUES = frozenset({"allowed", "anyone", "everyone", "public", "true", "on"})


@dataclass(frozen=True)
class ClassifiedChange:
    event_id: uuid.UUID
    change_class: ChangeClass
    significance: Significance
    entity_type: str
    entity_id: uuid.UUID
    label: str | None
    summary: str
    before: Any | None
    after: Any | None
    detected_at: datetime | None
    detail_path: str | None
    change_type: str
    field_changes: tuple[dict[str, Any], ...] = ()
    connector_instance_id: uuid.UUID | None = None
    application_display_name: str | None = None
    # Who did it, when the provider recorded it happening, and under what
    # action. Attached by `changes.overlay` from a matching audit row
    # and left None whenever no audit log is collected or nothing matches --
    # snapshot-diff itself cannot know an actor. Never affects classification.
    actor_email: str | None = None
    actor_provider_id: str | None = None
    actor_action: str | None = None
    actor_occurred_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "change_class": self.change_class.value,
            "significance": self.significance.value,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "label": self.label,
            "summary": self.summary,
            "before": self.before,
            "after": self.after,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "detail_path": self.detail_path,
            "change_type": self.change_type,
            "field_changes": list(self.field_changes),
            "connector_instance_id": (str(self.connector_instance_id) if self.connector_instance_id else None),
            "application_display_name": self.application_display_name,
            "actor_email": self.actor_email,
            "actor_provider_id": self.actor_provider_id,
            "actor_action": self.actor_action,
            "actor_occurred_at": (self.actor_occurred_at.isoformat() if self.actor_occurred_at else None),
        }


@dataclass(frozen=True)
class _Verdict:
    """A rule's answer before labels and summaries are attached."""

    change_class: ChangeClass
    significance: Significance
    before: Any | None = None
    after: Any | None = None


def _field_change(event: Event, field: str) -> dict[str, Any] | None:
    for change in event.field_changes or []:
        if change.get("field") == field:
            return change
    return None


def _grant_access_description(db: Session, grant: Grant | None) -> str:
    if grant is None:
        return "Access"
    level = (grant.permission_level or "").strip()
    if grant.role_id is not None:
        role = db.get(Role, grant.role_id)
        if role is not None:
            if level:
                return f"{level.title()} ({role.name})"
            return role.name
    if level:
        return level.title()
    return "Access"


def _oauth_app_scope_summary(db: Session, app_id: uuid.UUID) -> str:
    app = db.get(OAuthApplication, app_id)
    app_name = app.name if app is not None else "unknown app"
    scopes = list(
        db.scalars(
            select(OAuthScope.scope_name).where(OAuthScope.oauth_application_id == app_id).order_by(OAuthScope.scope_name)
        ).all()
    )
    if not scopes:
        return app_name
    if len(scopes) <= 3:
        return f"{app_name} ({', '.join(scopes)})"
    return f"{app_name} ({len(scopes)} scopes)"


def _group_name_from_label(label: str | None) -> str:
    if not label or " ∈ " not in label:
        return "group"
    return label.rsplit(" ∈ ", 1)[-1]


def _identity_status_description(db: Session, identity_id: uuid.UUID) -> str:
    identity = db.get(Identity, identity_id)
    if identity is None:
        return "Account"
    return identity.display_name or identity.email or identity.provider_object_id or "Account"


def _synthesize_evidence(
    db: Session,
    event: Event,
    verdict: _Verdict,
    label: str | None,
) -> tuple[Any | None, Any | None]:
    """Human-readable before/after for every change class, including creates/deletes."""
    if verdict.before is not None or verdict.after is not None:
        return verdict.before, verdict.after

    change_class = verdict.change_class

    if change_class in {ChangeClass.ADMIN_GRANTED, ChangeClass.ACCESS_GRANTED}:
        grant = db.get(Grant, event.entity_id)
        return None, _grant_access_description(db, grant)

    if change_class in {ChangeClass.ADMIN_REVOKED, ChangeClass.ACCESS_REVOKED}:
        grant = db.get(Grant, event.entity_id)
        return _grant_access_description(db, grant), None

    if change_class is ChangeClass.GROUP_MEMBER_ADDED:
        group_name = _group_name_from_label(label)
        membership = db.get(GroupMembership, event.entity_id)
        if membership is not None:
            group = db.get(Group, membership.group_id)
            if group is not None:
                group_name = group.name
        return "Not a member", f"Member of {group_name}"

    if change_class is ChangeClass.GROUP_MEMBER_REMOVED:
        group_name = _group_name_from_label(label)
        return f"Member of {group_name}", "Not a member"

    if change_class is ChangeClass.OAUTH_APP_INSTALLED:
        oauth_grant = db.get(OAuthGrant, event.entity_id)
        if oauth_grant is not None:
            return "Not authorized", _oauth_app_scope_summary(db, oauth_grant.oauth_application_id)
        return "Not authorized", label or "Authorized"

    if change_class is ChangeClass.OAUTH_APP_REVOKED:
        oauth_grant = db.get(OAuthGrant, event.entity_id)
        if oauth_grant is not None:
            return _oauth_app_scope_summary(db, oauth_grant.oauth_application_id), None
        return label or "Authorized", None

    if change_class is ChangeClass.IDENTITY_ADDED:
        return "Did not exist", _identity_status_description(db, event.entity_id)

    if change_class is ChangeClass.IDENTITY_REMOVED:
        return _identity_status_description(db, event.entity_id), "Removed"

    if change_class is ChangeClass.EXTERNAL_SHARING_ENABLED:
        return verdict.before, verdict.after

    if event.change_type is ChangeType.CREATED:
        return None, label or event.entity_type

    if event.change_type is ChangeType.DELETED:
        return label or event.entity_type, None

    if event.field_changes:
        first = event.field_changes[0]
        return first.get("old"), first.get("new")

    return None, None


def _is_privileged_grant(db: Session, grant: Grant | None) -> bool:
    if grant is None:
        return False
    if (grant.permission_level or "").lower() == "admin":
        return True
    if grant.role_id is None:
        return False
    role = db.get(Role, grant.role_id)
    return bool(role is not None and role.is_privileged)


def _permissive(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _PERMISSIVE_VALUES


def _classify_grant(db: Session, event: Event) -> _Verdict:
    grant = db.get(Grant, event.entity_id)

    if event.change_type is ChangeType.CREATED:
        if _is_privileged_grant(db, grant):
            return _Verdict(ChangeClass.ADMIN_GRANTED, Significance.HIGH)
        return _Verdict(ChangeClass.ACCESS_GRANTED, Significance.LOW)

    if event.change_type is ChangeType.DELETED:
        if _is_privileged_grant(db, grant):
            return _Verdict(ChangeClass.ADMIN_REVOKED, Significance.MEDIUM)
        return _Verdict(ChangeClass.ACCESS_REVOKED, Significance.LOW)

    level = _field_change(event, "permission_level")
    if level is None:
        return _Verdict(ChangeClass.OTHER, Significance.LOW)

    old, new = level.get("old"), level.get("new")
    old_rank = _PERMISSION_RANK.get(str(old).lower(), -1)
    new_rank = _PERMISSION_RANK.get(str(new).lower(), -1)
    if new_rank > old_rank:
        significance = Significance.HIGH if str(new).lower() == "admin" else Significance.MEDIUM
        return _Verdict(ChangeClass.PRIVILEGE_ESCALATED, significance, old, new)
    if new_rank < old_rank:
        return _Verdict(ChangeClass.PRIVILEGE_REDUCED, Significance.LOW, old, new)
    return _Verdict(ChangeClass.OTHER, Significance.LOW, old, new)


def _classify_group_membership(event: Event) -> _Verdict:
    if event.change_type is ChangeType.DELETED:
        return _Verdict(ChangeClass.GROUP_MEMBER_REMOVED, Significance.LOW)
    return _Verdict(ChangeClass.GROUP_MEMBER_ADDED, Significance.LOW)


def _classify_oauth_grant(db: Session, event: Event) -> _Verdict:
    if event.change_type is ChangeType.DELETED:
        return _Verdict(ChangeClass.OAUTH_APP_REVOKED, Significance.LOW)

    # An install matters in proportion to what the app can reach.
    grant = db.get(OAuthGrant, event.entity_id)
    sensitive = False
    if grant is not None:
        sensitive = bool(
            db.scalars(
                select(OAuthScope.id)
                .where(
                    OAuthScope.oauth_application_id == grant.oauth_application_id,
                    OAuthScope.is_sensitive.is_(True),
                )
                .limit(1)
            ).first()
        )
    significance = Significance.HIGH if sensitive else Significance.MEDIUM
    return _Verdict(ChangeClass.OAUTH_APP_INSTALLED, significance)


def _created_in_same_run(db: Session, event: Event) -> bool:
    """Whether this entity first appeared in the run that emitted ``event``."""
    return bool(
        db.scalars(
            select(Event.id)
            .where(
                Event.connector_run_id == event.connector_run_id,
                Event.entity_type == event.entity_type,
                Event.entity_id == event.entity_id,
                Event.change_type == ChangeType.CREATED,
            )
            .limit(1)
        ).first()
    )


def _classify_oauth_application(db: Session, event: Event) -> _Verdict | None:
    # An app row appearing, and that same run populating its scopes, are both
    # just "this app was installed" — which the paired oauth_grant already
    # reports, with the user who authorized it. Left alone, one install becomes
    # three rows. An app that already existed gaining its first scopes is a
    # real expansion, so this keys off the app being new, not off empty scopes.
    if event.change_type is ChangeType.CREATED:
        return None

    scopes = _field_change(event, "scopes")
    if scopes is None:
        return _Verdict(ChangeClass.CONFIG_DRIFT, Significance.LOW)

    if _created_in_same_run(db, event):
        return None

    old = set(scopes.get("old") or [])
    new = set(scopes.get("new") or [])
    added = new - old
    if not added:
        return _Verdict(ChangeClass.CONFIG_DRIFT, Significance.LOW, sorted(old), sorted(new))

    sensitive_added = bool(
        db.scalars(
            select(OAuthScope.id)
            .where(
                OAuthScope.oauth_application_id == event.entity_id,
                OAuthScope.scope_name.in_(added),
                OAuthScope.is_sensitive.is_(True),
            )
            .limit(1)
        ).first()
    )
    significance = Significance.HIGH if sensitive_added else Significance.MEDIUM
    return _Verdict(ChangeClass.OAUTH_SCOPE_EXPANDED, significance, sorted(old), sorted(new))


def _classify_setting(db: Session, event: Event) -> _Verdict:
    value = _field_change(event, "value")
    if value is None:
        return _Verdict(ChangeClass.CONFIG_DRIFT, Significance.LOW)

    old, new = value.get("old"), value.get("new")
    setting = db.get(TenantSetting, event.entity_id)
    category = (setting.category if setting is not None else "") or ""

    if category == "sharing" and _permissive(new) and not _permissive(old):
        return _Verdict(ChangeClass.EXTERNAL_SHARING_ENABLED, Significance.HIGH, old, new)

    significance = Significance.MEDIUM if category in _SENSITIVE_SETTING_CATEGORIES else Significance.LOW
    return _Verdict(ChangeClass.CONFIG_DRIFT, significance, old, new)


def _classify_identity(db: Session, event: Event) -> _Verdict:
    if event.change_type is ChangeType.CREATED:
        return _Verdict(ChangeClass.IDENTITY_ADDED, Significance.LOW)
    if event.change_type is ChangeType.DELETED:
        return _Verdict(ChangeClass.IDENTITY_REMOVED, Significance.LOW)

    mfa = _field_change(event, "mfa_enabled")
    # Only an explicit False is a disable. True -> None means the connector
    # lost visibility (a token that can no longer read 2FA status), which is
    # a coverage gap, not every account turning MFA off; it falls through
    # to a low-significance OTHER.
    if mfa is not None and mfa.get("old") is True and mfa.get("new") is False:
        identity = db.get(Identity, event.entity_id)
        # Losing MFA matters most on accounts that hold privilege.
        privileged = bool(
            identity is not None
            and db.scalars(
                select(Grant.id)
                .join(Role, Role.id == Grant.role_id)
                .where(Grant.identity_id == identity.id, Role.is_privileged.is_(True))
                .limit(1)
            ).first()
        )
        significance = Significance.HIGH if privileged else Significance.MEDIUM
        return _Verdict(ChangeClass.MFA_DISABLED, significance, mfa.get("old"), mfa.get("new"))

    disabled = _field_change(event, "is_disabled")
    if disabled is not None and disabled.get("new") is True:
        return _Verdict(ChangeClass.IDENTITY_DISABLED, Significance.LOW, disabled.get("old"), disabled.get("new"))

    return _Verdict(ChangeClass.OTHER, Significance.LOW)


_SUMMARY_TEMPLATES = {
    ChangeClass.ADMIN_GRANTED: "Admin access granted: {label}",
    ChangeClass.ADMIN_REVOKED: "Admin access revoked: {label}",
    ChangeClass.PRIVILEGE_ESCALATED: "Privilege escalated {before} → {after}: {label}",
    ChangeClass.PRIVILEGE_REDUCED: "Privilege reduced {before} → {after}: {label}",
    ChangeClass.ACCESS_GRANTED: "Access granted: {label}",
    ChangeClass.ACCESS_REVOKED: "Access revoked: {label}",
    ChangeClass.GROUP_MEMBER_ADDED: "Added to group: {label}",
    ChangeClass.GROUP_MEMBER_REMOVED: "Removed from group: {label}",
    ChangeClass.OAUTH_APP_INSTALLED: "OAuth app authorized: {label}",
    ChangeClass.OAUTH_APP_REVOKED: "OAuth authorization revoked: {label}",
    ChangeClass.OAUTH_SCOPE_EXPANDED: "OAuth scopes expanded: {label}",
    ChangeClass.EXTERNAL_SHARING_ENABLED: "External sharing enabled ({after}): {label}",
    ChangeClass.MFA_DISABLED: "MFA no longer enabled: {label}",
    ChangeClass.IDENTITY_DISABLED: "Account disabled: {label}",
    ChangeClass.IDENTITY_ADDED: "Account appeared: {label}",
    ChangeClass.IDENTITY_REMOVED: "Account disappeared: {label}",
    ChangeClass.CONFIG_DRIFT: "Configuration changed: {label}",
    ChangeClass.OTHER: "Changed: {label}",
}


def _summarize(verdict: _Verdict, label: str | None, entity_type: str) -> str:
    template = _SUMMARY_TEMPLATES[verdict.change_class]
    return template.format(
        label=label or entity_type,
        before=verdict.before if verdict.before is not None else "—",
        after=verdict.after if verdict.after is not None else "—",
    )


def classify_event(db: Session, org_id: uuid.UUID, event: Event) -> ClassifiedChange | None:
    """``None`` when the event has no standalone meaning — it is already
    reported as part of another change."""
    if event.entity_type == "grant":
        verdict = _classify_grant(db, event)
    elif event.entity_type == "group_membership":
        verdict = _classify_group_membership(event)
    elif event.entity_type == "oauth_grant":
        verdict = _classify_oauth_grant(db, event)
    elif event.entity_type in {"oauth_application", "oauth_app"}:
        app_verdict = _classify_oauth_application(db, event)
        if app_verdict is None:
            return None
        verdict = app_verdict
    elif event.entity_type == "setting":
        verdict = _classify_setting(db, event)
    elif event.entity_type == "identity":
        verdict = _classify_identity(db, event)
    else:
        verdict = _Verdict(ChangeClass.OTHER, Significance.LOW)

    label_info = entity_label(db, org_id, event.entity_type, event.entity_id)
    label = label_info["label"]
    before, after = _synthesize_evidence(db, event, verdict, label)
    field_changes = tuple(dict(fc) for fc in (event.field_changes or []))
    return ClassifiedChange(
        event_id=event.id,
        change_class=verdict.change_class,
        significance=verdict.significance,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        label=label,
        summary=_summarize(verdict, label, event.entity_type),
        before=before,
        after=after,
        detected_at=event.detected_at,
        detail_path=label_info["detail_path"],
        change_type=event.change_type.value,
        field_changes=field_changes,
    )


def classify_events(db: Session, org_id: uuid.UUID, events: Sequence[Event]) -> list[ClassifiedChange]:
    """Classified changes, most significant first, then most recent.

    Ordering is the point of the feed: an operator scanning a week of drift
    should hit the new admin before a hundred group memberships.
    """
    classified = [change for change in (classify_event(db, org_id, event) for event in events) if change is not None]
    classified.sort(
        key=lambda c: (
            _SIGNIFICANCE_ORDER[c.significance],
            -(c.detected_at.timestamp() if c.detected_at else 0),
        )
    )
    return classified
