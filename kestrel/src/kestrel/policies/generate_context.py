# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Workbench context for AI policy generate: catalog, samples, instance resolution."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.policies.dataload import load_identity_rows, load_setting_rows
from kestrel.policies.generate_catalog import (
    INTENT_TEMPLATES,
    OKTA_EVENT_ACTIONS,
    OKTA_PRIVILEGED_ROLES,
    OKTA_TENANT_SETTING_KEYS,
    connector_catalog_for_prompt,
    normalize_connector_hint,
)
from kestrel.policies.resource_schemas import RESOURCE_SCHEMAS

INTENT_CHIP_EXAMPLES: tuple[dict[str, str], ...] = (
    {
        "label": "Okta admins without MFA",
        "intent": "Detect Okta administrator without MFA enabled",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Okta MFA enroll not required",
        "intent": "Detect Okta org MFA enrollment not required",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
    {
        "label": "Disabled Okta privileged admin",
        "intent": "Detect disabled Okta privileged admin still assigned",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Weak Okta password policy",
        "intent": "Detect weak Okta password policy minimum length",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
    {
        "label": "Dormant Okta admin",
        "intent": "Detect dormant Okta privileged admin inactive 90 days",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Okta bookmark/SWA app",
        "intent": "Detect Okta apps using bookmark sign-on without SSO",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
)


def resolve_connector_hint(
    session: Session | None,
    org_id: uuid.UUID | None,
    *,
    connector_hint: str | None = None,
    application_instance_id: uuid.UUID | None = None,
) -> str | None:
    """Resolve connector slug from hint or connected application instance."""
    if connector_hint:
        return normalize_connector_hint(connector_hint)
    if session is None or org_id is None or application_instance_id is None:
        return None
    instance = session.get(ApplicationInstance, application_instance_id)
    if instance is None or instance.org_id != org_id:
        return None
    application = session.get(Application, instance.application_id)
    if application is None:
        return None
    return normalize_connector_hint(application.application_type.value)


def _redact_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return None
    domain = email.split("@", 1)[1]
    return f"***@{domain}"


def _redact_row(row: dict[str, Any]) -> dict[str, Any]:
    """Strip secrets and partial emails from a dataload row for LLM/workbench display."""
    identity = row.get("identity")
    if isinstance(identity, dict):
        identity = dict(identity)
        identity.pop("raw_source", None)
        identity.pop("provider_object_id", None)
        identity["email"] = _redact_email(identity.get("email"))
        row = {**row, "identity": identity}
    setting = row.get("setting")
    if isinstance(setting, dict):
        row = {**row, "setting": {k: setting[k] for k in ("key", "category", "label", "value_type") if k in setting}}
    event = row.get("event")
    if isinstance(event, dict):
        event = dict(event)
        event["actor_email"] = _redact_email(event.get("actor_email"))
        event["target_email"] = _redact_email(event.get("target_email"))
        row = {**row, "event": event}
    return row


def field_catalog(connector: str | None) -> dict[str, Any]:
    connector = normalize_connector_hint(connector)
    base = {
        "resource_types": list(RESOURCE_SCHEMAS.keys()),
        "schemas": RESOURCE_SCHEMAS,
    }
    if connector == "okta":
        base["okta"] = {
            "privileged_roles": list(OKTA_PRIVILEGED_ROLES),
            "tenant_setting_keys": list(OKTA_TENANT_SETTING_KEYS),
            "event_actions": list(OKTA_EVENT_ACTIONS),
            "identity_fields": [
                "email",
                "display_name",
                "mfa_enabled",
                "is_disabled",
                "is_external",
                "last_active_at",
                "identity_type",
            ],
            "prompt_catalog": connector_catalog_for_prompt("okta", None),
        }
    return base


def live_samples(
    session: Session,
    org_id: uuid.UUID,
    connector: str | None,
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    connector = normalize_connector_hint(connector)
    if connector != "okta":
        return []
    rows = load_identity_rows(session, org_id)
    filtered = [r for r in rows if (r.get("application") or {}).get("type") == "okta"]
    samples: list[dict[str, Any]] = []
    for row in filtered[:limit]:
        slim = {
            "_subject_id": row.get("_subject_id"),
            "identity": {
                k: row.get("identity", {}).get(k)
                for k in ("display_name", "mfa_enabled", "is_disabled", "last_active_at", "identity_type")
            },
            "application": row.get("application"),
            "roles": row.get("roles"),
        }
        samples.append(_redact_row(slim))
    settings = load_setting_rows(session, org_id)
    for row in settings:
        if (row.get("application") or {}).get("type") != "okta":
            continue
        key = (row.get("setting") or {}).get("key")
        if key and str(key).startswith(("mfa_", "password_", "threat_", "okta_app_")):
            samples.append(_redact_row({"setting": row.get("setting"), "application": row.get("application")}))
            if len(samples) >= limit + 2:
                break
    return samples[: limit + 2]


def generate_workbench_catalog(
    session: Session | None,
    org_id: uuid.UUID | None,
    *,
    connector_hint: str | None = None,
    application_instance_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    connector = resolve_connector_hint(
        session,
        org_id,
        connector_hint=connector_hint,
        application_instance_id=application_instance_id,
    )
    chips = [chip for chip in INTENT_CHIP_EXAMPLES if connector is None or chip.get("connector_hint") == connector]
    catalog: dict[str, Any] = {
        "connector": connector,
        "intent_chips": chips,
        "template_names": [t.name for t in INTENT_TEMPLATES],
        "fields": field_catalog(connector),
        "samples": [],
    }
    if session is not None and org_id is not None and connector:
        catalog["samples"] = live_samples(session, org_id, connector)
    return catalog
