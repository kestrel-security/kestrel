# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-disabled-org-admin"
TITLE = "Disabled GitHub identities that still hold the organization administrator role"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags disabled GitHub identities that still hold the organization administrator role"
REMEDIATION = (
    "Remove the organization administrator role from the disabled account, or restore and secure the "
    "account if access is still required."
)
COMPLIANCE = {"custom": ["GH-02"], "soc2": ["CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "github":
        return True
    if "organization_admin" not in roles:
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
