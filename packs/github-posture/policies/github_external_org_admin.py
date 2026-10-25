# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-external-org-admin"
TITLE = "Detect external GitHub identities with the organization administrator role"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect external GitHub identities with the organization administrator role"
REMEDIATION = "Remove organization administrator from external identities; use least-privilege collaborator access instead."
COMPLIANCE = {"custom": ["GH-03"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "github":
        return True
    if "organization_admin" not in roles:
        return True
    return not identity.get("is_external")


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_external": identity.get("is_external"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }
