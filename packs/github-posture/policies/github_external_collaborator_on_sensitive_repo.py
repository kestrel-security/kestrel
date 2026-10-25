# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-external-collaborator-on-sensitive-repo"
TITLE = "Outside collaborator has write or admin access to a sensitive repository"
SEVERITY = "critical"
RESOURCE_TYPE = "grant"
DESCRIPTION = (
    "An outside collaborator -- someone who is not a member of the organization, and so is not "
    "covered by its SSO, its MFA requirement, or its offboarding -- can push to a repository "
    "holding production, secret, or customer-facing code."
)
REMEDIATION = (
    "Drop the collaborator to read, replace the direct grant with a team the organization "
    "controls, or remove the access. If the work is ongoing, make them an organization member "
    "so SSO and offboarding apply."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"], "custom": ["GH-EXT-01"]}

WRITE_LEVELS = ("write", "admin", "maintain")


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    repo = resource.get("resource") or {}
    grant = resource.get("grant") or {}

    if application.get("type") != "github":
        return True
    if str(repo.get("resource_type") or "") != "repository":
        return True
    if not identity.get("is_external"):
        return True
    # `is_sensitive` is tri-state: None means no assessment has been made, and
    # guessing on it would either flood or hide. Only a positive answer fires.
    if repo.get("is_sensitive") is not True:
        return True
    return str(grant.get("permission_level") or "").lower() not in WRITE_LEVELS


def evidence(resource):
    identity = resource.get("identity") or {}
    repo = resource.get("resource") or {}
    grant = resource.get("grant") or {}
    application = resource.get("application") or {}
    config = repo.get("config") or {}
    return {
        "identity.display_name": identity.get("display_name"),
        "identity.email": identity.get("email"),
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.sensitivity_source": config.get("sensitivity_source"),
        "resource.sensitivity_reasons": config.get("sensitivity_reasons"),
        "grant.permission_level": grant.get("permission_level"),
        "grant.granted_via": grant.get("granted_via"),
        "application.name": application.get("name"),
    }
