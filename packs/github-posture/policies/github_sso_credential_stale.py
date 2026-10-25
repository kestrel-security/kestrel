# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-sso-credential-stale"
TITLE = "SAML SSO-authorized credentials that have not been used in months"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A personal access token or SSH key authorized for SSO keeps org access until revoked, whether or not"
    " anyone still uses it."
)
REMEDIATION = (
    "Revoke the credential's SSO authorization in Organization settings -> Single sign-on, and have the "
    "owner rotate it if still needed."
)
REQUIRES = ["github:org_security"]
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-1"], "cis": ["5.3"]}

STALE_DAYS = 90


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("sso_credential:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    age = days_since(value.get("last_accessed_at"))
    if age is None:
        # No usable last-access timestamp. GitHub does not always populate
        # `credential_accessed_at`, so absence is missing evidence rather than
        # evidence of disuse -- firing here would open a finding on every
        # credential in orgs where the field is never set. Compliant, and the
        # gap is stated in the setup doc rather than guessed at.
        return True
    return age <= STALE_DAYS


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "credential.login": value.get("login") if isinstance(value, dict) else None,
        "credential.type": value.get("credential_type") if isinstance(value, dict) else None,
        "credential.scopes": value.get("scopes") if isinstance(value, dict) else None,
        "credential.last_accessed_at": value.get("last_accessed_at") if isinstance(value, dict) else None,
        "application.name": application.get("name"),
    }
