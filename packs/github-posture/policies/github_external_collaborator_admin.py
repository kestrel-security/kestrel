# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-external-collaborator-admin"
TITLE = "Detect external collaborators with admin-level access to a GitHub repository"
SEVERITY = "high"
RESOURCE_TYPE = "grant"
DESCRIPTION = "Detect external collaborators with admin-level access to a GitHub repository"
REMEDIATION = "Review and remove admin access for external collaborators; grant only the minimum access required."
COMPLIANCE = {"custom": ["GH-03"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    grant = resource.get("grant") or {}
    if application.get("type") != "github":
        return True
    if not identity.get("is_external"):
        return True
    return grant.get("permission_level") != "admin"


def evidence(resource):
    identity = resource.get("identity") or {}
    resource_row = resource.get("resource") or {}
    grant = resource.get("grant") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "resource.name": resource_row.get("name"),
        "grant.granted_via": grant.get("granted_via"),
        "grant.permission_level": grant.get("permission_level"),
    }
