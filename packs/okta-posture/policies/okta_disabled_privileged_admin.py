# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-disabled-privileged-admin"
TITLE = "Disabled Okta users that still hold privileged admin roles"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags disabled Okta users that still hold privileged admin roles"
REMEDIATION = "Remove privileged admin roles from suspended or deprovisioned Okta accounts immediately."
COMPLIANCE = {"custom": ["OKTA-02"], "soc2": ["CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-1"]}

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
    return not identity.get("is_disabled")


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_disabled": identity.get("is_disabled"),
        "application.name": application.get("name"),
    }
