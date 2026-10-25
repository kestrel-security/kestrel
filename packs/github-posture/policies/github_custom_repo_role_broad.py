# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-custom-repo-role-broad"
TITLE = "Detect custom organization roles with privileged permissions"
SEVERITY = "medium"
RESOURCE_TYPE = "grant"
DESCRIPTION = (
    "A custom organization role includes administrative or management-level permissions. "
    "Custom roles that bundle admin capabilities may grant broader access than intended "
    "when assigned to members or teams. Review whether each permission is necessary "
    "for the role's stated purpose."
)
REMEDIATION = (
    "Review the custom role in GitHub organization settings → Member privileges → "
    "Custom repository roles. Remove administrative permissions (admin, manage, delete, "
    "push, create) that are not required for the role's purpose, applying the principle "
    "of least privilege. Consider splitting broad roles into focused, scoped roles."
)
REQUIRES = ["github:org_security"]
COMPLIANCE = {
    "nist_csf": ["PR.AC-4"],
    "soc2": ["CC6.1", "CC6.3"],
    "cis": ["6.1"],
}


def policy(resource):
    application = resource.get("application") or {}
    role = resource.get("role") or {}
    if application.get("type") != "github":
        return True
    if not role:
        return True
    # Custom org roles have provider_object_ids that start with "custom-org-role:".
    provider_id = str(role.get("provider_object_id") or "")
    if not provider_id.startswith("custom-org-role:"):
        return True
    return not role.get("is_privileged")


def evidence(resource):
    role = resource.get("role") or {}
    application = resource.get("application") or {}
    return {
        "role.name": role.get("name"),
        "role.is_privileged": role.get("is_privileged"),
        "role.provider_object_id": role.get("provider_object_id"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
