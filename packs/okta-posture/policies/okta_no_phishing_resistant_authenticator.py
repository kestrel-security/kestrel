# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-no-phishing-resistant-authenticator"
TITLE = "Detect Okta orgs with no phishing-resistant authenticator enabled"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Push and OTP factors can be relayed by an attacker-in-the-middle proxy, which is how most MFA bypass"
    " happens. Without WebAuthn or a smart card enabled, no rule can require a factor that resists it."
)
REMEDIATION = (
    "Enable WebAuthn (security key or biometric) in Security -> Authenticators, then require it on the "
    "policies protecting admin access."
)
REQUIRES = ["okta:authenticators"]
COMPLIANCE = {"custom": ["OKTA-01"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"], "cis": ["6.3"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("okta_authenticator:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    # Only the phishing-resistant ones can satisfy this; a phishable
    # authenticator being active says nothing either way, so it passes.
    if not value.get("phishing_resistant"):
        return True
    return str(value.get("status") or "").upper() == "ACTIVE"


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value")
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.label": setting.get("label"),
        "setting.value": value if not isinstance(value, dict) else {k: v for k, v in value.items() if k != "rules"},
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
