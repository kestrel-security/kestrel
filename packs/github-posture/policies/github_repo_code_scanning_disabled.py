# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-code-scanning-disabled"
TITLE = "Repositories without code scanning configured"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Code scanning is not configured on this repository. Without code scanning, "
    "common vulnerability patterns (injection, path traversal, insecure deserialization, "
    "etc.) are not automatically detected in pull requests or on push. GitHub Advanced "
    "Security default setup takes a few minutes to configure and covers the most common "
    "query suites for the repository's detected languages."
)
REMEDIATION = (
    "Enable code scanning via the repository's Security tab → Code scanning → "
    "Set up code scanning → Default setup. Select the default query suite for "
    "broad coverage, or extended for additional security checks. For custom "
    "workflows, configure CodeQL via Actions instead."
)
REQUIRES = ["github:code_scanning"]
COMPLIANCE = {
    "nist_csf": ["ID.RA-1", "PR.IP-1"],
    "soc2": ["CC6.1"],
    "cis": ["5.4"],
}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_code_scanning_setup")
    if setting is None:
        return True
    value = setting.get("value") or {}
    state = str(value.get("state") or "") if isinstance(value, dict) else str(value or "")
    # "configured" is the healthy state; "not-configured" or absent is the finding.
    return state == "configured"


def evidence(resource):
    repo = resource.get("resource") or {}
    settings = resource.get("settings_by_key") or {}
    application = resource.get("application") or {}
    setting = settings.get("repo_code_scanning_setup") or {}
    return {
        "resource.name": repo.get("name"),
        "resource.visibility": repo.get("visibility"),
        "resource.provider_object_id": repo.get("provider_object_id"),
        "code_scanning_state": (setting.get("value") or {}).get("state"),
        "application.name": application.get("name"),
    }
