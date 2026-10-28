# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Workbench context for AI policy generate: catalog, samples, instance resolution."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.policies.coverage import GENERIC_CAPABILITIES
from kestrel.policies.dataload import load_identity_rows, load_setting_rows
from kestrel.policies.generate_catalog import (
    CONNECTOR_PACKS,
    INTENT_TEMPLATES,
    OKTA_EVENT_ACTIONS,
    OKTA_PRIVILEGED_ROLES,
    OKTA_TENANT_SETTING_KEYS,
    connector_catalog_for_prompt,
    normalize_connector_hint,
    pack_catalog,
)
from kestrel.policies.generate_intent import CROSS_APP_CONNECTOR, SCOPE_CROSS_APP, SCOPE_SINGLE_APP
from kestrel.policies.resource_schemas import CROSS_APP_CATALOG, RESOURCE_SCHEMAS
from kestrel.policies.vocabulary import IDP_APPLICATION_TYPES, TRUSTED_ACTIVITY_SOURCES

INTENT_CHIP_EXAMPLES: tuple[dict[str, str], ...] = (
    {
        "label": "Okta admins without MFA",
        "intent": "Flag Okta administrator without MFA enabled",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Okta MFA enroll not required",
        "intent": "Flag Okta org MFA enrollment not required",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
    {
        "label": "Disabled Okta privileged admin",
        "intent": "Flag disabled Okta privileged admin still assigned",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Weak Okta password policy",
        "intent": "Flag weak Okta password policy minimum length",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
    {
        "label": "Dormant Okta admin",
        "intent": "Flag dormant Okta privileged admin inactive 90 days",
        "connector_hint": "okta",
        "resource_type": "identity",
    },
    {
        "label": "Okta bookmark/SWA app",
        "intent": "Flag Okta apps using bookmark sign-on without SSO",
        "connector_hint": "okta",
        "resource_type": "tenant_setting",
    },
    {
        "label": "Contractor dormant in an app",
        "intent": (
            "Identify contractors who have an account that's active in any app but haven't signed into that app "
            "in the last 30 days"
        ),
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "identity",
        "scope": SCOPE_CROSS_APP,
    },
    {
        "label": "Departed, still enabled a week later",
        "intent": (
            "Accounts still enabled in any app more than 7 days after the person was disabled in the identity provider"
        ),
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "identity",
        "scope": SCOPE_CROSS_APP,
    },
    {
        "label": "Admin without IdP MFA",
        "intent": "Admins in any connected app whose identity provider account has no MFA",
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "identity",
        "scope": SCOPE_CROSS_APP,
    },
    {
        "label": "Dormant everywhere",
        "intent": "People with enabled accounts who have been inactive in every app for 90 days",
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "identity",
        "scope": SCOPE_CROSS_APP,
    },
    {
        "label": "Contractor with sensitive OAuth consent",
        "intent": "Contractors or guests who consented to a third-party OAuth app with sensitive scopes",
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "identity",
        "scope": SCOPE_CROSS_APP,
    },
    {
        "label": "Privilege granted to departed user",
        "intent": "Admin privilege granted in any app to a user who was disabled in the identity provider",
        "connector_hint": CROSS_APP_CONNECTOR,
        "resource_type": "event",
        "scope": SCOPE_CROSS_APP,
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


def cross_app_catalog() -> dict[str, Any]:
    """The cross-application vocabulary the workbench shows beside the editor."""
    return {
        "cluster_fields": [
            "cluster.accounts[]",
            "cluster.idp_status",
            "cluster.idp_application_types",
            "cluster.worker_type",
            "cluster.last_active_at",
            "cluster.privileged_application_types",
            "cluster.is_representative",
        ],
        "worker_types": ["employee", "contractor", "vendor_or_partner", "guest", "service", "unknown"],
        "trusted_activity_sources": sorted(TRUSTED_ACTIVITY_SOURCES),
        "idp_application_types": sorted(IDP_APPLICATION_TYPES),
        "helpers": [
            "worker_type_of",
            "cluster_accounts",
            "idp_account",
            "is_representative",
            "has_privileged_role",
            "in_group",
            "activity_status",
            "trusted_last_active",
        ],
        "capabilities": dict(GENERIC_CAPABILITIES),
        "prompt_catalog": CROSS_APP_CATALOG,
    }


def field_catalog(connector: str | None, scope: str | None = None) -> dict[str, Any]:
    connector = normalize_connector_hint(connector)
    base = {
        "resource_types": list(RESOURCE_SCHEMAS.keys()),
        "schemas": RESOURCE_SCHEMAS,
        "scopes": [SCOPE_SINGLE_APP, SCOPE_CROSS_APP],
        "connectors": {
            name: catalog.to_dict()
            for name in CONNECTOR_PACKS
            if name != CROSS_APP_CONNECTOR and (catalog := pack_catalog(name)) is not None
        },
        "cross_app": cross_app_catalog(),
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
    scope: str | None = None,
) -> dict[str, Any]:
    connector = resolve_connector_hint(
        session,
        org_id,
        connector_hint=connector_hint,
        application_instance_id=application_instance_id,
    )
    if scope == SCOPE_CROSS_APP:
        chips = [chip for chip in INTENT_CHIP_EXAMPLES if chip.get("scope") == SCOPE_CROSS_APP]
    elif connector is None or connector == CROSS_APP_CONNECTOR:
        chips = list(INTENT_CHIP_EXAMPLES)
    else:
        # The selected application's chips, then the cross-app ones: a person
        # picking Okta still wants "contractors dormant in any app".
        chips = [chip for chip in INTENT_CHIP_EXAMPLES if chip.get("connector_hint") == connector] + [
            chip for chip in INTENT_CHIP_EXAMPLES if chip.get("scope") == SCOPE_CROSS_APP
        ]
    catalog: dict[str, Any] = {
        "connector": connector,
        "scope": scope,
        "intent_chips": chips,
        "template_names": [t.name for t in INTENT_TEMPLATES],
        "fields": field_catalog(connector, scope),
        "samples": [],
    }
    if session is not None and org_id is not None and connector and connector != CROSS_APP_CONNECTOR:
        catalog["samples"] = live_samples(session, org_id, connector)
    return catalog
