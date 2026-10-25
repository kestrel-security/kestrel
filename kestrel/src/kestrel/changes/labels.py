# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Human-readable labels for changed entities and relationships.

A change feed row identified only by ``grant`` plus a UUID is unreviewable, and
relationship rows are the worst case: their meaning lives entirely in what they
point at. Shared by the run-drift reader and the change classifier so both name
the same row the same way.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.access import Grant, Group, GroupMembership, Role
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting


def identity_name(db: Session, identity_id: uuid.UUID | None) -> str:
    if identity_id is None:
        return "—"
    identity = db.get(Identity, identity_id)
    if identity is None:
        return "unknown identity"
    return identity.display_name or identity.email or identity.provider_object_id


def _base(entity_type: str, entity_id: uuid.UUID) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "label": None,
        "detail_path": None,
    }


def _explore_identity(identity_id: uuid.UUID) -> str:
    return f"/explore?focus={identity_id}&focus_type=identity&direction=out"


def _explore_resource(resource_id: uuid.UUID) -> str:
    return f"/explore?focus={resource_id}&focus_type=resource&direction=in"


def _explore_oauth_app(app_id: uuid.UUID) -> str:
    return f"/explore?focus={app_id}&focus_type=oauth_application&direction=in"


def _identity_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    identity = db.get(Identity, entity_id)
    if identity is not None and identity.org_id == org_id:
        base["label"] = identity.display_name or identity.email or identity.provider_object_id
        base["detail_path"] = _explore_identity(identity.id)
    return base


def _resource_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    resource = db.get(Resource, entity_id)
    if resource is not None and resource.org_id == org_id:
        base["label"] = resource.name
        base["detail_path"] = _explore_resource(resource.id)
    return base


def _oauth_application_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    oauth_app = db.get(OAuthApplication, entity_id)
    if oauth_app is not None and oauth_app.org_id == org_id:
        base["label"] = oauth_app.name
        base["detail_path"] = _explore_oauth_app(oauth_app.id)
    return base


def _setting_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    setting = db.get(TenantSetting, entity_id)
    if setting is not None and setting.org_id == org_id:
        base["label"] = setting.label or setting.key
    return base


def _grant_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    """Render a grant as "who → what → at what level"."""
    grant = db.get(Grant, entity_id)
    if grant is None or grant.org_id != org_id:
        return base

    subject = identity_name(db, grant.identity_id)
    if grant.identity_id is None and grant.source_group_id is not None:
        group = db.get(Group, grant.source_group_id)
        subject = f"group {group.name}" if group is not None else "unknown group"

    target = None
    if grant.resource_id is not None:
        resource = db.get(Resource, grant.resource_id)
        target = resource.name if resource is not None else None
    if target is None and grant.role_id is not None:
        role = db.get(Role, grant.role_id)
        target = role.name if role is not None else None

    level = grant.permission_level or (grant.granted_via.value if grant.granted_via else None)
    base["label"] = f"{subject} → {target or 'organization'}" + (f" ({level})" if level else "")
    if grant.identity_id is not None:
        base["detail_path"] = _explore_identity(grant.identity_id)
    elif grant.resource_id is not None:
        base["detail_path"] = _explore_resource(grant.resource_id)
    return base


def _group_membership_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    membership = db.get(GroupMembership, entity_id)
    if membership is None or membership.org_id != org_id:
        return base
    group = db.get(Group, membership.group_id)
    group_name = group.name if group is not None else "unknown group"
    base["label"] = f"{identity_name(db, membership.identity_id)} ∈ {group_name}"
    base["detail_path"] = _explore_identity(membership.identity_id)
    return base


def _oauth_grant_label(db: Session, org_id: uuid.UUID, base: dict[str, Any], entity_id: uuid.UUID) -> dict[str, Any]:
    grant = db.get(OAuthGrant, entity_id)
    if grant is None or grant.org_id != org_id:
        return base
    app = db.get(OAuthApplication, grant.oauth_application_id)
    app_name = app.name if app is not None else "unknown app"
    base["label"] = f"{identity_name(db, grant.identity_id)} → {app_name}"
    if grant.identity_id is not None:
        base["detail_path"] = _explore_identity(grant.identity_id)
    elif app is not None:
        base["detail_path"] = _explore_oauth_app(app.id)
    return base


_LABELERS = {
    "identity": _identity_label,
    "resource": _resource_label,
    "oauth_application": _oauth_application_label,
    "oauth_app": _oauth_application_label,
    "setting": _setting_label,
    "grant": _grant_label,
    "group_membership": _group_membership_label,
    "oauth_grant": _oauth_grant_label,
}


def entity_label(db: Session, org_id: uuid.UUID, entity_type: str, entity_id: uuid.UUID) -> dict[str, Any]:
    """``{entity_type, entity_id, label, detail_path}``; label is ``None`` for
    kinds with no renderer or rows outside ``org_id``."""
    base = _base(entity_type, entity_id)
    labeler = _LABELERS.get(entity_type)
    return labeler(db, org_id, base, entity_id) if labeler else base
