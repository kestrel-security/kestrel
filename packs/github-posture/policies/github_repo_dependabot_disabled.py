# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-dependabot-disabled"
TITLE = "Repositories with Dependabot security updates disabled"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = "Without Dependabot security updates, a vulnerable dependency stays vulnerable until someone notices."
REMEDIATION = "Enable Dependabot security updates in the repository's code security settings."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"nist_csf": ["PR.IP-1"], "soc2": ["CC6.1"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_dependabot_security_updates_enabled")
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
