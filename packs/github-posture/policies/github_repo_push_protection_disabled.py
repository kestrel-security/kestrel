# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-push-protection-disabled"
TITLE = "Detect repositories with secret scanning push protection disabled"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Push protection blocks a credential before it reaches the repository. Without it, detection happens "
    "only after the secret is already in the history."
)
REMEDIATION = "Enable push protection alongside secret scanning in the repository's security settings."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["DE.CM-7"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_secret_scanning_push_protection_enabled")
    if setting is None:
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
