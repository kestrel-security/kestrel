# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resource row shapes for AI prompts and fixture demos."""

from __future__ import annotations

import json

from kestrel.policies.cross_app_fixtures import CONTRACTOR_DORMANT_IN_APP
from kestrel.policies.generate_catalog import (
    OKTA_EVENT_FIXTURES,
    OKTA_IDENTITY_FIXTURES,
    OKTA_TENANT_SETTING_FIXTURES,
    normalize_connector_hint,
)
from kestrel.policies.generate_intent import CROSS_APP_CONNECTOR, SCOPE_CROSS_APP

RESOURCE_SCHEMAS: dict[str, str] = {
    "identity": """Row shape for RESOURCE_TYPE=identity (one row per ACCOUNT in one application):
{
  "_subject_type": "identity",
  "_subject_id": "<uuid>",
  "identity": {
    "email": str|None, "display_name": str|None,
    "identity_type": "user"|"service_account"|"external_identity",
    "mfa_enabled": bool|None,            # None = the connector could not read it
    "is_disabled": bool, "is_external": bool,   # is_external = this app's guest flag, NOT "contractor"
    "worker_type": "employee"|"contractor"|"vendor_or_partner"|"guest"|"service"|"unknown",
    "worker_type_source": "connector"|"rule:<id>"|None,
    "department": str|None, "title": str|None, "manager_email": str|None,
    "last_active_at": datetime|None,
    "last_active_source": "login"|"audit"|"analytics"|"profile"|None,  # profile is NOT activity
    "created_at_source": datetime|None, "disabled_at": datetime|None, "expires_at": datetime|None,
    "attributes": {"org_unit_path": str, "guest_type": str, "is_admin": bool, "user_type": str, ...},
    "provider_object_id": str
  },
  "application": {
    "type": "github"|"google_workspace"|"slack"|"okta"|"custom",
    "name": str, "display_name": str|None, "external_tenant_ref": str|None, "status": str|None
  },
  "roles": ["Super Administrator", "organization_admin", ...],   # this account's role names
  "groups": ["engineering", "contractors-emea", "/Contractors", ...],   # group names in this app
  "settings": [...], "settings_by_key": {"<key>": {"key": str, "value": ...}},   # per-identity settings
  "oauth_grants": [ {"oauth_application_name": str, "publisher": str|None, "is_verified": bool|None,
                     "sensitive_scope_names": [str], "granted_at": datetime|None, "last_used_at": datetime|None} ],
  "_related": {"grants": [ <grant rows for this account> ]},
  "privileged_application_types": ["github", "okta", ...],
  "cluster": {                      # the same PERSON's accounts across every connected application
    "accounts": [ {"identity_id": str, "application_type": str, "application_name": str,
                   "identity_type": str, "email": str|None, "display_name": str|None,
                   "is_disabled": bool, "is_external": bool, "mfa_enabled": bool|None,
                   "worker_type": str, "roles": [str], "privileged": bool, "groups": [str],
                   "last_active_at": datetime|None, "last_active_source": str|None,
                   "created_at_source": datetime|None, "disabled_at": datetime|None,
                   "expires_at": datetime|None, "department": str|None} ],   # includes THIS account
    "member_count": int, "active_account_count": int,
    "application_types": [str],
    "idp_status": "active"|"disabled"|"absent",   # the identity provider's account for this person
    "idp_application_types": ["okta"|"google_workspace"], "idp_connected": bool,
    "privileged_application_types": [str],
    "worker_type": str, "worker_type_source": "idp"|"other"|"none",   # the person's resolved worker type
    "last_active_at": datetime|None, "last_active_source": str|None,  # latest TRUSTED activity on any account
    "department": str|None,
    "representative_identity_id": str, "is_representative": bool,     # one row per person carries per-person findings
    "match_kind": "email"|"display_name"|"self"
  },
  "org": {"connected_application_types": [str], "idp_application_types": [str], "idp_connected": bool,
          "company_email_domains": [str]}
}
Helpers that read this shape: worker_type_of(resource), cluster_accounts(resource, ...), idp_account(resource),
is_representative(resource), has_privileged_role(row_or_account), in_group(resource, patterns),
activity_status(row_or_account, days), trusted_last_active(row_or_account).""",
    "grant": """Row shape for RESOURCE_TYPE=grant:
{
  "_subject_type": "identity"|"resource",
  "_subject_id": "<uuid>",
  "grant": {"granted_via": "direct"|"group", "permission_level": str|None},
  "identity": {"email": str|None, "is_external": bool, "is_disabled": bool, "worker_type": str, ...},
  "resource": {"name": str, "resource_type": str, "visibility": str|None, "is_sensitive": bool|None},
  "role": {"name": str, "is_privileged": bool},
  "application": {"type": str, "name": str},
  "org": {...}
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
    "attributes": {...},        # provider-specific detail; always a dict
    "actor": {"identity_id": str, "email": str|None, "display_name": str|None, "identity_type": str,
              "is_disabled": bool, "is_external": bool, "worker_type": str, "privileged": bool,
              "cluster_worker_type": str|None, "cluster_idp_status": "active"|"disabled"|"absent"|None,
              "representative_identity_id": str|None} | None,   # the identity the event was done BY
    "target": { same shape } | None                               # the identity the event was done TO
  },
  "application": {"type": str, "name": str},
  "org": {...}
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
    "oauth_application": """Row shape for RESOURCE_TYPE=oauth_application
(one row per third-party or installed app that holds grants in a connected tenant):
{
  "_subject_type": "oauth_application",
  "_subject_id": "<uuid>",
  "oauth_application": {"name": str, "publisher": str|None, "is_verified": bool|None, "provider_object_id": str},
  "sensitive_scope_names": [str],
  "last_used_at": datetime|None,
  "grant_count": int,
  "application": {"type": str, "name": str}
}
Return False to open a finding on that OAuth application; True if compliant.""",
}

#: What every cross-application draft is told about the cluster, beyond the row shape.
CROSS_APP_CATALOG = """Cross-application policies (application.type == any connected app):
- One identity row per ACCOUNT. policy() runs once per account in every application; it must NOT
  early-return on application.get("type"). Skip rows by identity_type (bots) and, when the identity
  provider's own account is the correct end state, skip rows whose application.type is in
  cluster["idp_application_types"].
- resource["cluster"] is the same person's other accounts. Read it with cluster_accounts(resource, ...),
  idp_account(resource), worker_type_of(resource), has_privileged_role(account), is_representative(resource).
- Report the finding on the account an operator must act on: the surviving or privileged account, never
  the identity-provider account that is already disabled. For a per-PERSON check (admin in two apps,
  dormant everywhere) gate with `if not is_representative(resource): return True` so one person is one finding.
- worker_type comes from the provider's profile and operator classification rules and may be "unknown".
  Use worker_type_of(resource) (the identity provider's account wins). Decide what unknown means
  (usually "not shown to be a contractor": return True) and say so in DESCRIPTION. is_external is
  the application's guest flag, not "contractor".
- Only last_active_source in ("login", "audit", "analytics") is activity; "profile" is not. Use
  activity_status(resource, DAYS) -> "active" | "stale" | "never" | "unknown"; treat "unknown" as not
  assessable (return True). GitHub's audit log only sees administrative actions, so a GitHub account
  with no observation is "unknown", not dormant.
- cluster["idp_status"]: "active" (the person's IdP account is enabled), "disabled" (they have been
  offboarded in the IdP), "absent" (no IdP account at all; check cluster["idp_connected"] first).
- Timestamps per account: last_active_at, created_at_source, disabled_at (when the IdP disabled it),
  expires_at (a guest's expiry). Use within_last_days / days_since on them.
- Set REQUIRES to the identity:* keys the policy reads (identity:last_sign_in, identity:worker_type,
  identity:groups, identity:disabled_at, identity:expires_at, identity:oauth_grants, identity:department)
  so a tenant whose connectors do not collect them reports "not assessable" instead of silently passing."""

FIXTURE_DEMOS: dict[str, str] = {
    "resource": """{
  "rows": [
    {
      "_subject_id": "repo-unprotected",
      "resource": {"resource_type": "repository", "name": "payments-api", "visibility": "private", "is_sensitive": true},
      "settings": [{"key": "repo_default_branch_protected", "value": false, "category": "security", "value_bool": false}],
      "settings_by_key": {"repo_default_branch_protected": {"key": "repo_default_branch_protected", "value": false}},
      "application": {"type": "github", "name": "GitHub"}
    },
    {
      "_subject_id": "repo-protected",
      "resource": {"resource_type": "repository", "name": "docs-site", "visibility": "public", "is_sensitive": false},
      "settings": [{"key": "repo_default_branch_protected", "value": true, "category": "security", "value_bool": true}],
      "settings_by_key": {"repo_default_branch_protected": {"key": "repo_default_branch_protected", "value": true}},
      "application": {"type": "github", "name": "GitHub"}
    }
  ],
  "expected_match_subject_ids": ["repo-unprotected"]
}""",
    "oauth_application": """{
  "rows": [
    {
      "_subject_id": "app-unverified-sensitive",
      "oauth_application": {"name": "Mail Merge Pro", "publisher": "Unknown Vendor", "is_verified": false,
                            "provider_object_id": "a1"},
      "sensitive_scope_names": ["https://www.googleapis.com/auth/gmail.readonly"],
      "last_used_at": {"$days_ago": 2},
      "grant_count": 12,
      "application": {"type": "google_workspace", "name": "Google Workspace"}
    },
    {
      "_subject_id": "app-verified-benign",
      "oauth_application": {"name": "Calendar Widget", "publisher": "Example Co", "is_verified": true,
                            "provider_object_id": "a2"},
      "sensitive_scope_names": [],
      "last_used_at": {"$days_ago": 2},
      "grant_count": 3,
      "application": {"type": "google_workspace", "name": "Google Workspace"}
    }
  ],
  "expected_match_subject_ids": ["app-unverified-sensitive"]
}""",
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
    CROSS_APP_CONNECTOR: {
        "identity": json.dumps(CONTRACTOR_DORMANT_IN_APP),
    },
}


def schema_docs_for_prompt(resource_type: str | None = None, *, scope: str | None = None) -> str:
    """Return schema documentation block(s) for the LLM system/user prompt.

    A cross-application draft gets the identity shape (and the event shape,
    which carries actor/target identity context) rather than every family:
    the identity shape is large and the cluster is what the draft is about.
    """
    if resource_type and resource_type in RESOURCE_SCHEMAS:
        return RESOURCE_SCHEMAS[resource_type]
    if scope == SCOPE_CROSS_APP:
        return "\n\n".join(RESOURCE_SCHEMAS[k] for k in ("identity", "event"))
    return "\n\n".join(RESOURCE_SCHEMAS[k] for k in ("identity", "grant", "application", "tenant_setting", "event"))


def fixture_demo_for(resource_type: str | None, connector_hint: str | None = None) -> str:
    key = resource_type if resource_type in FIXTURE_DEMOS else "identity"
    connector = normalize_connector_hint(connector_hint)
    if connector and connector in CONNECTOR_FIXTURE_DEMOS:
        connector_demos = CONNECTOR_FIXTURE_DEMOS[connector]
        if key in connector_demos:
            return connector_demos[key]
    return FIXTURE_DEMOS[key]
