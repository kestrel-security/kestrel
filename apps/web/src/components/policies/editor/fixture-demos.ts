// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Generic per-resource-type fixture scaffolds offered in the Fixtures panel.
 *
 * Extracted from `policy-editor.tsx` so the ~110 lines of JSON literals don't
 * dominate the component that owns the editor layout.
 */
export const FIXTURE_DEMOS: Record<string, string> = {
  identity: `{
  "rows": [
    {
      "_subject_id": "alice-id",
      "identity": {"email": "alice@acme.example", "mfa_enabled": false, "display_name": "alice"},
      "application": {"type": "github", "name": "GitHub"},
      "roles": ["organization_admin"]
    },
    {
      "_subject_id": "bob-id",
      "identity": {"email": "bob@acme.example", "mfa_enabled": true, "display_name": "bob"},
      "application": {"type": "github", "name": "GitHub"},
      "roles": ["organization_admin"]
    }
  ],
  "expected_match_subject_ids": ["alice-id"]
}`,
  grant: `{
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
}`,
  tenant_setting: `{
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
}`,
  event: `{
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
}`,
  application: `{
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
}`,
};

/** `RESOURCE_TYPE = "..."` parsed out of the policy source; identity is the default. */
export function detectResourceType(source: string): string {
  const match = source.match(/RESOURCE_TYPE\s*=\s*["']([a-z_]+)["']/);
  return match?.[1] ?? "identity";
}

export function fixtureDemoKey(resourceType: string): string {
  return resourceType in FIXTURE_DEMOS ? resourceType : "identity";
}
