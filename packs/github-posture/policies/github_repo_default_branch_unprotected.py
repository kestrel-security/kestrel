# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-default-branch-unprotected"
TITLE = "Repositories whose default branch has no protection"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "An unprotected default branch accepts direct pushes with no review, so any collaborator can change shipped code alone."
)
REMEDIATION = "Add a branch protection rule or an active ruleset covering the default branch, requiring review before merge."
REQUIRES = ["github:branch_protection"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.IP-1"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_default_branch_protected")
    if setting is None:
        # Not deep-scanned, so there is no evidence either way.
        return True
    return setting.get("value") is not False


def evidence(resource):
    repo = resource.get("resource") or {}
    settings = resource.get("settings_by_key") or {}
    application = resource.get("application") or {}
    return {
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.provider_object_id": repo.get("provider_object_id"),
        "settings": sorted(settings.keys()),
        "application.name": application.get("name"),
    }
