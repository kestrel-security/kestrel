# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-open-secret-scanning-alerts"
TITLE = "Repositories with unresolved secret-scanning alerts"
SEVERITY = "critical"
RESOURCE_TYPE = "resource"
DESCRIPTION = "An open secret-scanning alert means a credential is present in the repository and has not been revoked."
REMEDIATION = "Revoke and rotate the exposed credential, then close the alert. Removing the commit alone does not revoke it."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"], "cis": ["5.3"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_open_secret_scanning_alerts")
    if setting is None:
        return True
    return int(setting.get("value") or 0) == 0


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
