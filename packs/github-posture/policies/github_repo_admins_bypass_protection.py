# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-admins-bypass-protection"
TITLE = "Detect protected branches that administrators can bypass"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Without 'Include administrators', branch protection does not apply to the people most able to abuse "
    "it, and to anyone who compromises them."
)
REMEDIATION = "Enable 'Do not allow bypassing the above settings' (enforce_admins) on the branch protection rule."
REQUIRES = ["github:branch_protection"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_branch_protection_detail")
    if setting is None:
        return True
    detail = setting.get("value") or {}
    if not isinstance(detail, dict) or not detail.get("protected"):
        return True
    return detail.get("enforce_admins") is not False


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
