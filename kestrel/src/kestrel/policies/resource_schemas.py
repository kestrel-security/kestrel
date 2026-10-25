# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resource row shapes for AI prompts and fixture demos."""

from __future__ import annotations

import json

from kestrel.policies.generate_catalog import (
    OKTA_EVENT_FIXTURES,
    OKTA_IDENTITY_FIXTURES,
    OKTA_TENANT_SETTING_FIXTURES,
    normalize_connector_hint,
)

RESOURCE_SCHEMAS: dict[str, str] = {
    "identity": """Row shape for RESOURCE_TYPE=identity:
{
  "_subject_type": "identity",
  "_subject_id": "<uuid>",
  "identity": {
    "email": str|None, "display_name": str|None,
    "identity_type": "user"|"service_account"|"external_identity",
    "mfa_enabled": bool|None, "is_disabled": bool, "is_external": bool,
    "last_active_at": datetime|None, "created_at_source": datetime|None,
    "provider_object_id": str
  },
  "application": {
    "type": "github"|"google_workspace"|"slack"|"okta"|"custom",
    "name": str, "display_name": str|None, "external_tenant_ref": str|None, "status": str|None
  },
  "roles": ["Super Administrator", "organization_admin", ...],
  "privileged_application_types": ["github", "okta", ...]
}""",
    "grant": """Row shape for RESOURCE_TYPE=grant:
{
  "_subject_type": "identity"|"resource",
  "_subject_id": "<uuid>",
  "grant": {"granted_via": "direct"|"group", "permission_level": str|None},
  "identity": {...}, "resource": {...}, "role": {"name": str, "is_privileged": bool},
  "application": {"type": str, "name": str}
}""",
    "tenant_setting": """Row shape for RESOURCE_TYPE=tenant_setting:
{
  "_subject_type": "setting",
  "_subject_id": "<uuid>",
  "setting": {
    "key": str, "category": str|None, "label": str|None,
    "value": bool|str|number|object, "value_bool": bool|None, "value_type": str|None
  },
  "application": {"type": str, "name": str}
}""",
    "event": """Row shape for RESOURCE_TYPE=event (SaaS activity / audit logs):
{
  "_subject_type": "event",
  "_subject_id": "<uuid>",
  "event": {
    "action": str,              # e.g. "mfa.disable", "privilege.grant"
    "action_category": str|None,
    "actor_email": str|None, "actor_provider_id": str|None,
    "target_email": str|None, "target_type": str|None, "target_provider_id": str|None,
    "occurred_at": datetime, "summary": str|None,
    "attributes": {...}         # provider-specific detail; always a dict
  },
  "application": {"type": str, "name": str}
}
Return False to open a finding on that event; True if compliant / ignore.""",
    "resource": """Row shape for RESOURCE_TYPE=resource
(repositories, channels, drives, SharePoint sites):
{
  "_subject_type": "resource",
  "_subject_id": "<uuid>",
  "resource": {
    "resource_type": "repository"|"channel"|"drive_file"|"shared_drive"|"sharepoint_site"|"custom",
    "name": str,
    "visibility": "public"|"private"|"internal"|None,
    "is_sensitive": bool|None,
    "provider_object_id": str
  },
  "settings": [ {"key": str, "value": ..., "category": str, "value_bool": bool|None}, ... ],
  "settings_by_key": {"<key>": {"key": str, "value": ..., ...}},
  "application": {"type": str, "name": str}
}
`settings` holds the per-resource settings that govern this one resource (a
branch protection rule, a channel sharing control) -- tenant-wide settings are
not here, they are RESOURCE_TYPE=tenant_setting. Both are empty when the
connector collects no per-resource settings, so index defensively:
`row["settings_by_key"].get("branch_protection_enabled", {}).get("value")`.
Return False to open a finding on that resource; True if compliant.""",
    "application": """Row shape for RESOURCE_TYPE=application
(one row per ApplicationInstance / connected SaaS tenant):
{
  "_subject_type": "application",
  "_subject_id": "<uuid>",
  "application": {
    "type": "github"|"google_workspace"|"slack"|"okta"|"custom",
    "name": str,
    "display_name": str,
    "external_tenant_ref": str,
    "status": "active"|"error"|"disabled"
  }
}
Return False to open a finding on that connected app; True if compliant.""",
}

FIXTURE_DEMOS: dict[str, str] = {
    "identity": """{
  "rows": [
    {
      "_subject_id": "alice-id",
      "identity": {
        "email": "alice@acme.example", "mfa_enabled": false, "display_name": "Alice", "is_disabled": false,
        "last_active_at": {"$days_ago": 120}
      },
      "application": {"type": "github", "name": "GitHub"},
      "roles": ["organization_admin"]
    },
    {
      "_subject_id": "bob-id",
      "identity": {
        "email": "bob@acme.example", "mfa_enabled": true, "display_name": "Bob", "is_disabled": false,
        "last_active_at": {"$days_ago": 5}
      },
      "application": {"type": "github", "name": "GitHub"},
      "roles": ["organization_admin"]
    }
  ],
  "expected_match_subject_ids": ["alice-id"]
}""",
    "grant": """{
  "rows": [
    {
      "_subject_id": "grant-direct",
      "grant": {"granted_via": "direct", "permission_level": "admin"},
      "identity": {"email": "erin@acme.example", "is_external": false},
      "resource": {"name": "secrets-vault", "resource_type": "repository"},
      "role": {},
      "application": {"type": "github", "name": "GitHub"}
    },
    {
      "_subject_id": "grant-group",
      "grant": {"granted_via": "group", "permission_level": "write"},
      "identity": {"email": "bob@acme.example"},
      "resource": {"name": "web-app", "resource_type": "repository"},
      "role": {},
      "application": {"type": "github", "name": "GitHub"}
    }
  ],
  "expected_match_subject_ids": ["grant-direct"]
}""",
    "tenant_setting": """{
  "rows": [
    {
      "_subject_id": "setting-mfa",
      "setting": {"key": "require_mfa", "value": false, "value_bool": false, "category": "security"},
      "application": {"type": "github", "name": "GitHub"}
    },
    {
      "_subject_id": "setting-ok",
      "setting": {"key": "require_mfa", "value": true, "value_bool": true, "category": "security"},
      "application": {"type": "slack", "name": "Slack"}
    }
  ],
  "expected_match_subject_ids": ["setting-mfa"]
}""",
    "event": """{
  "rows": [
    {
      "_subject_id": "evt-mfa-off",
      "event": {
        "action": "mfa.disable",
        "action_category": "auth",
        "actor_email": "alice@acme.example",
        "target_email": "alice@acme.example",
        "occurred_at": "2026-07-29T12:00:00+00:00",
        "summary": "MFA disabled for alice"
      },
      "application": {"type": "github", "name": "GitHub"}
    },
    {
      "_subject_id": "evt-login",
      "event": {
        "action": "user.login",
        "actor_email": "bob@acme.example",
        "occurred_at": "2026-07-29T12:00:00+00:00",
        "summary": "User login"
      },
      "application": {"type": "github", "name": "GitHub"}
    }
  ],
  "expected_match_subject_ids": ["evt-mfa-off"]
}""",
    "application": """{
  "rows": [
    {
      "_subject_id": "app-disabled",
      "application": {
        "type": "github",
        "name": "GitHub",
        "display_name": "Acme GitHub (legacy)",
        "external_tenant_ref": "acme-legacy",
        "status": "disabled"
      }
    },
    {
      "_subject_id": "app-ok",
      "application": {
        "type": "slack",
        "name": "Slack",
        "display_name": "Acme Slack",
        "external_tenant_ref": "T0ACMEWORK",
        "status": "active"
      }
    }
  ],
  "expected_match_subject_ids": ["app-disabled"]
}""",
}

# Connector-specific fixture overrides (used when connector_hint is set).
CONNECTOR_FIXTURE_DEMOS: dict[str, dict[str, str]] = {
    "okta": {
        "identity": json.dumps(OKTA_IDENTITY_FIXTURES),
        "tenant_setting": json.dumps(OKTA_TENANT_SETTING_FIXTURES),
        "event": json.dumps(OKTA_EVENT_FIXTURES),
    },
}


def schema_docs_for_prompt(resource_type: str | None = None) -> str:
    """Return schema documentation block(s) for the LLM system/user prompt."""
    if resource_type and resource_type in RESOURCE_SCHEMAS:
        return RESOURCE_SCHEMAS[resource_type]
    return "\n\n".join(RESOURCE_SCHEMAS[k] for k in ("identity", "grant", "application", "tenant_setting", "event"))


def fixture_demo_for(resource_type: str | None, connector_hint: str | None = None) -> str:
    key = resource_type if resource_type in FIXTURE_DEMOS else "identity"
    connector = normalize_connector_hint(connector_hint)
    if connector and connector in CONNECTOR_FIXTURE_DEMOS:
        connector_demos = CONNECTOR_FIXTURE_DEMOS[connector]
        if key in connector_demos:
            return connector_demos[key]
    return FIXTURE_DEMOS[key]
