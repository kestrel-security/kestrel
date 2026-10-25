# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-admin-without-mfa"
TITLE = "Detect Okta Super / Org / App / Help Desk / Group admins without MFA"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect Okta Super / Org / App / Help Desk / Group admins without MFA"
REMEDIATION = "Require MFA for the privileged Okta admin, or remove the admin role assignment."
COMPLIANCE = {"custom": ["OKTA-02"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}

OKTA_PRIVILEGED_ROLES = (
    "Super Administrator",
    "Organization Administrator",
    "Application Administrator",
    "Help Desk Administrator",
    "Group Administrator",
)


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "okta":
        return True
    if not any(r in roles for r in OKTA_PRIVILEGED_ROLES):
        return True
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }
