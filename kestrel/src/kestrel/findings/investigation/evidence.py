# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Evidence rows enriched with remediator labels, grouping, highlights, and deep-links."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingEvidence, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.findings.investigation._common import _findings_list_path
from kestrel.findings.investigation.subject import _application_remediation_context, _subject_application_instance_id

# Friendly evidence labels for remediator UI (dotted keys stay as API id).
_EVIDENCE_DISPLAY_LABELS: dict[str, str] = {
    "setting.key": "Setting key",
    "setting.value": "Current value",
    "setting.label": "Setting",
    "setting.category": "Category",
    "setting.description": "Description",
    "application.name": "Application",
    "application.type": "Application type",
    "application.display_name": "Connected tenant",
    "application.external_tenant_ref": "Tenant ref",
    "application.status": "Tenant status",
    "identity.email": "Email",
    "identity.display_name": "Name",
    "identity.mfa_enabled": "MFA enabled",
    "identity.is_external": "External",
    "identity.is_disabled": "Disabled",
    "identity.identity_type": "Identity type",
    "identity.roles": "Roles",
    "identity.privileged_application_types": "Privileged apps",
    "resource.name": "Resource",
    "resource.resource_type": "Resource type",
    "grant.granted_via": "Granted via",
    "grant.permission_level": "Permission",
    "role.name": "Role",
    "event.action": "Action",
    "event.actor_email": "Actor",
    "event.target_email": "Target",
    "event.occurred_at": "Occurred at",
    "event.summary": "Summary",
}


def _link(rel: str, href: str, title: str) -> dict[str, str]:
    return {"rel": rel, "href": href, "title": title}


def _dedupe_links(links: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for link in links:
        key = link["href"]
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out


def _resolve_resource_by_name(
    db: Session,
    *,
    org_id: uuid.UUID,
    name: str,
    application_instance_id: uuid.UUID | None,
) -> Resource | None:
    cleaned = name.strip()
    if not cleaned:
        return None
    stmt = select(Resource).where(Resource.org_id == org_id, Resource.name == cleaned)
    if application_instance_id is not None:
        stmt = stmt.where(Resource.application_instance_id == application_instance_id)
    return db.scalars(stmt.limit(1)).first()


def _resolve_identity_by_email(db: Session, *, org_id: uuid.UUID, email: str) -> Identity | None:
    cleaned = email.strip()
    if not cleaned or "@" not in cleaned:
        return None
    return db.scalars(
        select(Identity).where(Identity.org_id == org_id, Identity.email == cleaned, Identity.deleted_at.is_(None)).limit(1)
    ).first()


def _evidence_display_label(label: str) -> str:
    return _EVIDENCE_DISPLAY_LABELS.get(label, label.replace(".", " · ").replace("_", " "))


def _evidence_group(label: str) -> str:
    if not label or "." not in label:
        return "other"
    return label.split(".", 1)[0]


def _evidence_highlight(label: str, value: Any) -> bool:
    """Mark fields remediator should notice first (current value / risk flags)."""
    if label in {
        "setting.value",
        "identity.mfa_enabled",
        "identity.roles",
        "grant.permission_level",
        "grant.granted_via",
        "event.action",
    }:
        return True
    if label.endswith("mfa_enabled") and value is False:
        return True
    return label in {"identity.is_external", "identity.is_disabled"} and value is True


def evidence_with_links(
    db: Session,
    finding: Finding,
    evidence_rows: list[FindingEvidence] | None = None,
) -> list[dict[str, Any]]:
    """Evidence rows enriched with remediator labels and live deep-links.

    Links prefer findings-scoped and connector surfaces; optional provider
    console URLs are attached on matching prefixes.
    """
    rows = evidence_rows
    if rows is None:
        rows = list(db.scalars(select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)).all())

    app_instance_id = _subject_application_instance_id(db, finding)
    app_ctx = _application_remediation_context(
        db,
        org_id=finding.org_id,
        application_instance_id=app_instance_id,
        setting_key=None,
        for_identity=finding.subject_type == FindingSubjectType.IDENTITY,
    )
    if finding.subject_type == FindingSubjectType.SETTING:
        setting = db.get(TenantSetting, finding.subject_id)
        if setting is not None and setting.org_id == finding.org_id:
            app_ctx = _application_remediation_context(
                db,
                org_id=finding.org_id,
                application_instance_id=setting.application_instance_id,
                setting_key=setting.key,
            )

    subject_findings = _link(
        "findings",
        _findings_list_path(finding.subject_type, finding.subject_id),
        "Findings for subject",
    )
    connector_links: list[dict[str, str]] = []
    if app_ctx.get("connector_path"):
        connector_links.append(_link("connector", app_ctx["connector_path"], "Connector"))
    if app_ctx.get("provider_console_url"):
        connector_links.append(
            _link(
                "provider",
                app_ctx["provider_console_url"],
                app_ctx.get("provider_console_label") or "Open in provider",
            )
        )

    subject_links = [subject_findings, *connector_links]

    enriched: list[dict[str, Any]] = []
    for row in rows:
        label = row.label
        value = row.value
        prefix = label.split(".", 1)[0] if label else ""
        links: list[dict[str, str]] = []

        if prefix in {"identity", "resource", "setting", "event", "oauth_application"}:
            if (
                (prefix == "identity" and finding.subject_type == FindingSubjectType.IDENTITY)
                or (prefix == "resource" and finding.subject_type == FindingSubjectType.RESOURCE)
                or (prefix == "setting" and finding.subject_type == FindingSubjectType.SETTING)
                or (prefix == "event" and finding.subject_type == FindingSubjectType.EVENT)
                or (prefix == "oauth_application" and finding.subject_type == FindingSubjectType.OAUTH_APPLICATION)
            ):
                links.extend(subject_links)
            elif prefix == "identity" and isinstance(value, str):
                identity = _resolve_identity_by_email(db, org_id=finding.org_id, email=value)
                if identity is not None:
                    links.append(
                        _link(
                            "findings",
                            _findings_list_path(FindingSubjectType.IDENTITY, identity.id),
                            "Identity findings",
                        )
                    )
            elif label == "resource.name" and isinstance(value, str):
                resource = _resolve_resource_by_name(
                    db,
                    org_id=finding.org_id,
                    name=value,
                    application_instance_id=app_instance_id,
                )
                if resource is not None:
                    links.append(
                        _link(
                            "findings",
                            _findings_list_path(FindingSubjectType.RESOURCE, resource.id),
                            "Resource findings",
                        )
                    )
        elif prefix == "application":
            links.extend(connector_links)
        elif prefix == "grant":
            # Grant findings are usually keyed to the identity subject.
            if finding.subject_type == FindingSubjectType.IDENTITY:
                links.extend(subject_links)
            links.extend(connector_links)

        enriched.append(
            {
                "label": label,
                "display_label": _evidence_display_label(label),
                "group": _evidence_group(label),
                "highlight": _evidence_highlight(label, value),
                "value": value,
                "links": _dedupe_links(links),
            }
        )
    return enriched
