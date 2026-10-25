# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-writable-deploy-key"
TITLE = "Detect repositories with write-capable deploy keys"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "A writable deploy key is a push credential that sits outside the member and team model and outlives whoever added it."
)
REMEDIATION = "Replace the key with a read-only deploy key, or move the workflow to a GitHub App installation token."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"], "cis": ["5.1"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    for key, setting in settings.items():
        if not key.startswith("repo_deploy_key:"):
            continue
        value = setting.get("value") or {}
        if isinstance(value, dict) and value.get("read_only") is False:
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
