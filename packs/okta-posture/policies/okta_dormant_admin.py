# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-dormant-admin"
TITLE = "Privileged Okta admins inactive for 90+ days"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags privileged Okta administrators whose last login is older than 90 days."
REMEDIATION = "Review the dormant admin account, remove unnecessary privileges, or confirm continued need."
COMPLIANCE = {"custom": ["OKTA-02"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}

OKTA_PRIVILEGED_ROLES = (
    "Super Administrator",
    "Organization Administrator",
    "Application Administrator",
    "Help Desk Administrator",
    "Group Administrator",
)
DORMANT_DAYS = 90


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "okta":
        return True
    if not any(r in roles for r in OKTA_PRIVILEGED_ROLES):
        return True
    return within_last_days(identity.get("last_active_at"), DORMANT_DAYS)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "application.name": application.get("name"),
    }
