# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-environment-without-reviewers"
TITLE = "Detect deployment environments with no required reviewers"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Deployment environments hold their own secrets; one without required reviewers deploys on any qualifying workflow run."
)
REMEDIATION = "Add required reviewers to the environment, or move its secrets to a repository that gates deployment."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    for key, setting in settings.items():
        if not key.startswith("repo_environment:"):
            continue
        value = setting.get("value") or {}
        if isinstance(value, dict) and value.get("has_reviewers") is False:
            return False
    return True


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
