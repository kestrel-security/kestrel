# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-direct-repo-admin"
TITLE = "Identities with direct (non-team) admin access to a GitHub repository"
SEVERITY = "medium"
RESOURCE_TYPE = "grant"
DESCRIPTION = "Flags identities with direct (non-team) admin access to a GitHub repository"
REMEDIATION = "Convert direct repository admin grants to team-based access, or document why direct access is required."
COMPLIANCE = {"custom": ["GH-04"], "soc2": ["CC6.1"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    grant = resource.get("grant") or {}
    if application.get("type") != "github":
        return True
    if grant.get("granted_via") != "direct":
        return True
    return grant.get("permission_level") != "admin"


def evidence(resource):
    identity = resource.get("identity") or {}
    resource_row = resource.get("resource") or {}
    grant = resource.get("grant") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_external": identity.get("is_external"),
        "resource.name": resource_row.get("name"),
        "resource.resource_type": resource_row.get("resource_type"),
        "grant.granted_via": grant.get("granted_via"),
        "grant.permission_level": grant.get("permission_level"),
        "application.name": application.get("name"),
        "application.display_name": application.get("display_name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
