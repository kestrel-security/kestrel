# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-required-checks-missing"
TITLE = "Repositories with branch protection but no required status checks"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "The repository's default branch has protection enabled but no required status "
    "checks are configured. A branch protection rule without required checks prevents "
    "force pushes and requires reviews, but does not verify that CI passes before "
    "merging. Code that breaks the build or fails tests can be merged into the "
    "default branch."
)
REMEDIATION = (
    "In the repository settings → Branches → Branch protection rules, edit the rule "
    "for the default branch and enable 'Require status checks to pass before merging'. "
    "Add the CI checks that must pass (build, test, lint). Consider also enabling "
    "'Require branches to be up to date before merging' to prevent merge races."
)
REQUIRES = ["github:branch_protection"]
COMPLIANCE = {
    "nist_csf": ["PR.IP-1"],
    "soc2": ["CC8.1"],
    "cis": ["3.1"],
}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    protection_detail = settings.get("repo_branch_protection_detail")
    if protection_detail is None:
        return True
    value = protection_detail.get("value") or {}
    if not isinstance(value, dict):
        return True
    # Only flag when the branch IS protected but has no required status checks.
    if not value.get("protected"):
        return True
    return bool(value.get("required_status_checks"))


def evidence(resource):
    repo = resource.get("resource") or {}
    settings = resource.get("settings_by_key") or {}
    application = resource.get("application") or {}
    detail = settings.get("repo_branch_protection_detail") or {}
    return {
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.provider_object_id": repo.get("provider_object_id"),
        "branch_protection_detail": detail.get("value"),
        "application.name": application.get("name"),
    }
