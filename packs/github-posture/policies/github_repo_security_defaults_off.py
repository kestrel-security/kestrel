# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-security-defaults-off"
TITLE = "Repositories with vulnerability alerts disabled"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Dependabot vulnerability alerts are disabled on this repository. Without alerts, "
    "no notification is sent when a dependency with a known vulnerability is introduced. "
    "The repository's dependencies are unmonitored for security advisories."
)
REMEDIATION = (
    "Enable vulnerability alerts in the repository settings → Security and analysis → "
    "Dependabot → Dependabot alerts. For organization-wide defaults, configure "
    "automatic enablement in organization settings → Security → Code security "
    "and analysis → Automatically enable for new repositories."
)
REQUIRES = ["github:repo_security"]
COMPLIANCE = {
    "nist_csf": ["ID.RA-1", "DE.AE-2"],
    "soc2": ["CC6.1"],
    "cis": ["5.3"],
}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_vulnerability_alerts_enabled")
    if setting is None:
        return True
    return setting.get("value") is not False


def evidence(resource):
    repo = resource.get("resource") or {}
    settings = resource.get("settings_by_key") or {}
    application = resource.get("application") or {}
    setting = settings.get("repo_vulnerability_alerts_enabled") or {}
    return {
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.provider_object_id": repo.get("provider_object_id"),
        "vulnerability_alerts_enabled": setting.get("value"),
        "application.name": application.get("name"),
    }
