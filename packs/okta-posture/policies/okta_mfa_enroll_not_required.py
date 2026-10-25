# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-mfa-enroll-not-required"
TITLE = "Detect an Okta MFA enrollment policy that requires no factor"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The active Okta MFA enrollment policy leaves every factor optional, so users can sign in "
    "with a password alone until they choose to enroll."
)
REMEDIATION = (
    "In Okta, set at least one authenticator to Required in Security → Authenticators → "
    "Enrollment for the active enrollment policy."
)
COMPLIANCE = {"custom": ["OKTA-02"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    # Read from the MFA_ENROLL policy itself. `GET /api/v1/org` carries no
    # security configuration, so there is no org-level equivalent to read.
    if setting.get("key") != "mfa_enroll_policy_required":
        return True
    return setting.get("value") is not False


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
