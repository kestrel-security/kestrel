# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-disabled-help-desk-admin"
TITLE = "Detect suspended or archived Google Workspace users that still hold Help Desk Admin"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect suspended or archived Google Workspace users that still hold Help Desk Admin"
REMEDIATION = (
    "Remove the Help Desk Admin role from the suspended/archived account immediately. Help Desk Admins can reset passwords."
)
COMPLIANCE = {"cisa": ["GWS-02"], "soc2": ["CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "google_workspace":
        return True
    if "Help Desk Admin" not in roles:
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
