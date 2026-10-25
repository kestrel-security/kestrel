# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-approved-pat-admin-permissions"
TITLE = "Detect approved fine-grained PATs with organization administration permissions"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A fine-grained PAT has been approved for org access and includes organization "
    "administration write permissions. Fine-grained PATs with administration write access "
    "can change organization settings, manage members, and perform other privileged "
    "operations. Unlike GitHub App installations, these tokens are not scoped to a "
    "specific application identity, making it harder to audit their usage."
)
REMEDIATION = (
    "Review the approved PAT in GitHub organization settings → Third-party access → "
    "Fine-grained personal access tokens. If administration write permission is not "
    "required for the PAT's purpose, revoke it and ask the owner to request a "
    "new token with only the permissions they need. Consider requiring token expiry "
    "for tokens with administration permissions."
)
REQUIRES = ["github:org_security"]
COMPLIANCE = {
    "nist_csf": ["PR.AC-1", "PR.AC-4"],
    "soc2": ["CC6.1", "CC6.3"],
    "cis": ["6.1"],
}

# Permission names that indicate privileged org-level access.
PRIVILEGED_ORG_PERMISSIONS = frozenset({"administration", "members", "hooks", "secrets"})
WRITE_LEVELS = frozenset({"write", "admin"})


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if not str(setting.get("key") or "").startswith("approved_pat:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    permissions = value.get("permissions") or []
    for perm in permissions:
        if not isinstance(perm, dict):
            continue
        name = str(perm.get("name") or "")
        level = str(perm.get("level") or "").lower()
        scope = str(perm.get("scope") or "")
        if scope == "organization" and name in PRIVILEGED_ORG_PERMISSIONS and level in WRITE_LEVELS:
            return False
    return True


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "pat.owner": value.get("owner") if isinstance(value, dict) else None,
        "pat.repository_selection": value.get("repository_selection") if isinstance(value, dict) else None,
        "pat.permissions": value.get("permissions") if isinstance(value, dict) else None,
        "pat.access_granted_at": value.get("access_granted_at") if isinstance(value, dict) else None,
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
