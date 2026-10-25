# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-dependabot-critical-alerts"
TITLE = "Detect repositories with open Dependabot alerts"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "The repository has open Dependabot vulnerability alerts. Each alert means "
    "a dependency with a known security vulnerability is present in the codebase "
    "and has not been resolved. Kestrel collects alert counts only — advisory "
    "details are not stored."
)
REMEDIATION = (
    "Review open Dependabot alerts in the repository's Security tab and update "
    "the affected dependencies. For critical and high severity alerts, prioritize "
    "remediation before the next release. Enable auto-merge for Dependabot PRs "
    "on low-risk updates."
)
REQUIRES = ["github:dependabot_alerts"]
COMPLIANCE = {
    "nist_csf": ["ID.RA-1", "PR.IP-12"],
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
    setting = settings.get("repo_open_dependabot_alerts")
    if setting is None:
        return True
    return int(setting.get("value") or 0) == 0


def evidence(resource):
    repo = resource.get("resource") or {}
    settings = resource.get("settings_by_key") or {}
    application = resource.get("application") or {}
    setting = settings.get("repo_open_dependabot_alerts") or {}
    return {
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.provider_object_id": repo.get("provider_object_id"),
        "open_dependabot_alert_count": setting.get("value"),
        "application.name": application.get("name"),
    }
