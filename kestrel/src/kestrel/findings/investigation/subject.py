# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Subject resolution: label, deep-links, and remediator context for a finding's subject.

`resolve_subject` never blocks triage: a missing inventory row still yields
the subject's type and id.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.connector import ConnectorInstance
from kestrel.db.models.finding import Finding, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.findings.investigation._common import _findings_list_path, _identity_explore_path

# GitHub org console deep-links by tenant setting key.
_GITHUB_SETTING_CONSOLE: dict[str, tuple[str, str]] = {
    "two_factor_requirement_enabled": (
        "https://github.com/organizations/{org}/settings/security",
        "Open GitHub authentication security",
    ),
    "default_repository_permission": (
        "https://github.com/organizations/{org}/settings/member_privileges",
        "Open GitHub member privileges",
    ),
    "members_can_create_repositories": (
        "https://github.com/organizations/{org}/settings/member_privileges",
        "Open GitHub member privileges",
    ),
    "members_can_create_public_repositories": (
        "https://github.com/organizations/{org}/settings/member_privileges",
        "Open GitHub member privileges",
    ),
    "members_can_fork_private_repositories": (
        "https://github.com/organizations/{org}/settings/member_privileges",
        "Open GitHub member privileges",
    ),
}


def _subject_application_instance_id(db: Session, finding: Finding) -> uuid.UUID | None:
    """Best-effort app instance for connector / evidence deep-links."""
    if finding.subject_type == FindingSubjectType.IDENTITY:
        identity = db.get(Identity, finding.subject_id)
        if identity is not None and identity.org_id == finding.org_id:
            return identity.application_instance_id
    elif finding.subject_type == FindingSubjectType.RESOURCE:
        resource = db.get(Resource, finding.subject_id)
        if resource is not None and resource.org_id == finding.org_id:
            return resource.application_instance_id
    elif finding.subject_type == FindingSubjectType.OAUTH_APPLICATION:
        app = db.get(OAuthApplication, finding.subject_id)
        if app is not None and app.org_id == finding.org_id:
            return app.application_instance_id
    elif finding.subject_type == FindingSubjectType.SETTING:
        setting = db.get(TenantSetting, finding.subject_id)
        if setting is not None and setting.org_id == finding.org_id:
            return setting.application_instance_id
    elif finding.subject_type == FindingSubjectType.EVENT:
        event = db.get(ActivityEvent, finding.subject_id)
        if event is not None and event.org_id == finding.org_id:
            return event.application_instance_id
    elif finding.subject_type == FindingSubjectType.APPLICATION:
        # Subject id is the ApplicationInstance id for RESOURCE_TYPE=application.
        instance = db.get(ApplicationInstance, finding.subject_id)
        if instance is not None and instance.org_id == finding.org_id:
            return instance.id
    return None


def _connector_for_app_instance(
    db: Session, *, org_id: uuid.UUID, application_instance_id: uuid.UUID
) -> ConnectorInstance | None:
    return db.scalars(
        select(ConnectorInstance).where(
            ConnectorInstance.org_id == org_id,
            ConnectorInstance.application_instance_id == application_instance_id,
        )
    ).first()


def _provider_console_for_setting(
    *,
    application_type: str | None,
    external_tenant_ref: str | None,
    setting_key: str | None,
) -> tuple[str | None, str | None]:
    if not application_type or not external_tenant_ref:
        return None, None
    org = external_tenant_ref.strip()
    if not org:
        return None, None
    if application_type == ApplicationType.GITHUB.value:
        if setting_key and setting_key in _GITHUB_SETTING_CONSOLE:
            url_tmpl, label = _GITHUB_SETTING_CONSOLE[setting_key]
            return url_tmpl.format(org=org), label
        return (
            f"https://github.com/organizations/{org}/settings",
            "Open GitHub organization settings",
        )
    return None, None


def _provider_console_for_identity(
    *,
    application_type: str | None,
    external_tenant_ref: str | None,
) -> tuple[str | None, str | None]:
    if not application_type or not external_tenant_ref:
        return None, None
    org = external_tenant_ref.strip()
    if not org:
        return None, None
    if application_type == ApplicationType.GITHUB.value:
        return f"https://github.com/orgs/{org}/people", "Open GitHub people"
    return None, None


def _application_remediation_context(
    db: Session,
    *,
    org_id: uuid.UUID,
    application_instance_id: uuid.UUID | None,
    setting_key: str | None = None,
    for_identity: bool = False,
) -> dict[str, Any]:
    """Shared app + connector + provider console context for subject cards."""
    empty: dict[str, Any] = {
        "application_instance_id": None,
        "application_display_name": None,
        "application_type": None,
        "external_tenant_ref": None,
        "connector_instance_id": None,
        "connector_path": None,
        "provider_console_url": None,
        "provider_console_label": None,
    }
    if application_instance_id is None:
        return empty

    instance = db.get(ApplicationInstance, application_instance_id)
    if instance is None or instance.org_id != org_id:
        return empty

    application = db.get(Application, instance.application_id)
    app_type = application.application_type.value if application is not None else None
    connector = _connector_for_app_instance(db, org_id=org_id, application_instance_id=application_instance_id)
    connector_id = connector.id if connector is not None else None
    connector_path = f"/connectors/{connector_id}" if connector_id is not None else None

    if for_identity:
        console_url, console_label = _provider_console_for_identity(
            application_type=app_type,
            external_tenant_ref=instance.external_tenant_ref,
        )
    else:
        console_url, console_label = _provider_console_for_setting(
            application_type=app_type,
            external_tenant_ref=instance.external_tenant_ref,
            setting_key=setting_key,
        )

    return {
        "application_instance_id": application_instance_id,
        "application_display_name": instance.display_name,
        "application_type": app_type,
        "external_tenant_ref": instance.external_tenant_ref,
        "connector_instance_id": connector_id,
        "connector_path": connector_path,
        "provider_console_url": console_url,
        "provider_console_label": console_label,
    }


def _identity_subject(db: Session, finding: Finding, base: dict) -> dict:
    identity = db.get(Identity, finding.subject_id)
    if identity is None or identity.org_id != finding.org_id:
        return base
    label = identity.display_name or identity.email or identity.provider_object_id
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=identity.application_instance_id,
        for_identity=True,
    )
    return {
        **base,
        "label": label,
        "detail_path": f"/identities/{identity.id}",
        "graph_focus_path": _identity_explore_path(identity.id),
        "secondary": identity.email,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "provider_console_url": app_ctx["provider_console_url"],
        "provider_console_label": app_ctx["provider_console_label"],
        "context": {
            **app_ctx,
            "display_name": identity.display_name,
            "email": identity.email,
            "mfa_enabled": identity.mfa_enabled,
            "is_external": identity.is_external,
            "is_disabled": identity.is_disabled,
            "identity_type": identity.identity_type.value if identity.identity_type else None,
        },
    }


def _resource_subject(db: Session, finding: Finding, base: dict) -> dict:
    resource = db.get(Resource, finding.subject_id)
    if resource is None or resource.org_id != finding.org_id:
        return base
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=resource.application_instance_id,
    )
    return {
        **base,
        "label": resource.name,
        "detail_path": base["findings_list_path"],
        "secondary": resource.resource_type.value,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "provider_console_url": app_ctx["provider_console_url"],
        "provider_console_label": app_ctx["provider_console_label"],
        "context": {**app_ctx, "resource_type": resource.resource_type.value},
    }


def _oauth_application_subject(db: Session, finding: Finding, base: dict) -> dict:
    app = db.get(OAuthApplication, finding.subject_id)
    if app is None or app.org_id != finding.org_id:
        return base
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=app.application_instance_id,
    )
    return {
        **base,
        "label": app.name,
        "detail_path": base["findings_list_path"],
        "secondary": None,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "context": app_ctx,
    }


def _setting_subject(db: Session, finding: Finding, base: dict) -> dict:
    setting = db.get(TenantSetting, finding.subject_id)
    if setting is None or setting.org_id != finding.org_id:
        return base
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=setting.application_instance_id,
        setting_key=setting.key,
    )
    # Prefer connector instance page as the in-app subject destination.
    detail = app_ctx["connector_path"] or base["findings_list_path"]
    return {
        **base,
        "label": setting.label or setting.key,
        "detail_path": detail,
        "secondary": setting.key,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "provider_console_url": app_ctx["provider_console_url"],
        "provider_console_label": app_ctx["provider_console_label"],
        "context": {
            **app_ctx,
            "setting_key": setting.key,
            "setting_label": setting.label,
            "setting_value": setting.value,
            "setting_value_type": setting.value_type,
            "setting_category": setting.category,
            "setting_description": setting.description,
        },
    }


def _event_subject(db: Session, finding: Finding, base: dict) -> dict:
    event = db.get(ActivityEvent, finding.subject_id)
    if event is None or event.org_id != finding.org_id:
        return base
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=event.application_instance_id,
    )
    return {
        **base,
        "label": event.summary or event.action,
        "detail_path": base["findings_list_path"],
        "secondary": event.action,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "context": {
            **app_ctx,
            "action": event.action,
            "summary": event.summary,
            "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        },
    }


def _application_subject(db: Session, finding: Finding, base: dict) -> dict:
    instance = db.get(ApplicationInstance, finding.subject_id)
    if instance is None or instance.org_id != finding.org_id:
        return base
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=instance.id,
    )
    return {
        **base,
        "label": instance.display_name,
        "detail_path": app_ctx["connector_path"] or base["findings_list_path"],
        "secondary": instance.external_tenant_ref,
        "connector_path": app_ctx["connector_path"],
        "inventory_path": app_ctx["connector_path"],
        "provider_console_url": app_ctx["provider_console_url"],
        "provider_console_label": app_ctx["provider_console_label"],
        "context": {
            **app_ctx,
            "status": instance.status.value if instance.status else None,
        },
    }


# One builder per subject type. Each takes the type-agnostic `base` dict and
# returns it unchanged when the inventory row is missing or belongs to another org.
_SUBJECT_BUILDERS: dict[FindingSubjectType, Callable[[Session, Finding, dict], dict]] = {
    FindingSubjectType.IDENTITY: _identity_subject,
    FindingSubjectType.RESOURCE: _resource_subject,
    FindingSubjectType.OAUTH_APPLICATION: _oauth_application_subject,
    FindingSubjectType.SETTING: _setting_subject,
    FindingSubjectType.EVENT: _event_subject,
    FindingSubjectType.APPLICATION: _application_subject,
}


def resolve_subject(db: Session, finding: Finding) -> dict:
    """Best-effort subject label + remediator context for investigation UI.

    Missing inventory rows still return type + id so triage is not blocked.
    Identities link to their detail page and Explore; other subjects link to
    their connector or findings list, plus optional provider console URLs.
    """
    subject_type = finding.subject_type
    subject_id = finding.subject_id
    base: dict = {
        "type": subject_type.value,
        "id": subject_id,
        "label": None,
        "detail_path": None,
        "secondary": None,
        "findings_list_path": _findings_list_path(subject_type, subject_id),
        "graph_focus_path": None,
        "inventory_path": None,
        "connector_path": None,
        "provider_console_url": None,
        "provider_console_label": None,
        "context": {},
    }

    app_instance_id = _subject_application_instance_id(db, finding)

    builder = _SUBJECT_BUILDERS.get(subject_type)
    if builder is not None:
        return builder(db, finding, base)

    if app_instance_id is not None:
        app_ctx = _application_remediation_context(db, org_id=finding.org_id, application_instance_id=app_instance_id)
        base["connector_path"] = app_ctx["connector_path"]
        base["inventory_path"] = app_ctx["connector_path"]
        base["context"] = app_ctx

    return base


_NAME_KEYS = ("name", "display_name", "label", "title")
_LIST_PREVIEW = 3


def display_setting_value(value: Any) -> str | None:
    """A short human string for a setting value, or None when there is no
    readable one. Never a dict or list repr: object-valued settings (an Okta
    policy and its rules) show their name, lists of scalars a short preview."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    if isinstance(value, dict):
        for key in _NAME_KEYS:
            name = value.get(key)
            if isinstance(name, (str, int)) and not isinstance(name, bool) and str(name).strip():
                return str(name).strip()
        return None
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        if all(isinstance(item, (str, int, float)) and not isinstance(item, bool) for item in value):
            shown = ", ".join(str(item) for item in value[:_LIST_PREVIEW])
            extra = len(value) - _LIST_PREVIEW
            return f"{shown} +{extra} more" if extra > 0 else shown
        return f"{len(value)} items"
    return None


def subject_label_for_list(db: Session, finding: Finding) -> tuple[str | None, str | None]:
    """Lightweight (label, secondary) for findings list rows."""
    subject = resolve_subject(db, finding)
    label = subject.get("label")
    secondary = subject.get("secondary")
    ctx = subject.get("context") or {}
    if finding.subject_type == FindingSubjectType.SETTING and "setting_value" in ctx:
        shown = display_setting_value(ctx["setting_value"])
        if shown is not None:
            secondary = f"{secondary} = {shown}" if secondary else shown
    elif finding.subject_type == FindingSubjectType.IDENTITY:
        bits = []
        if ctx.get("mfa_enabled") is False:
            bits.append("MFA off")
        if ctx.get("is_external"):
            bits.append("external")
        if ctx.get("is_disabled"):
            bits.append("disabled")
        if bits:
            secondary = " · ".join(bits) if not secondary else f"{secondary} · {' · '.join(bits)}"
    return label, secondary
