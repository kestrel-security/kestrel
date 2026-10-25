# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-no-required-reviews"
TITLE = "Detect protected branches that require no approving review"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Branch protection without a required review lets a single person merge their own change into the default branch."
)
REMEDIATION = "Require at least one approving review, and require code owner review on repositories with a CODEOWNERS file."
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
    setting = settings.get("repo_branch_protection_detail")
    if setting is None:
        return True
    detail = setting.get("value") or {}
    if not isinstance(detail, dict) or not detail.get("protected"):
        return True
    required = detail.get("required_reviews")
    if required is None:
        return False
    return int(required) >= 1


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
