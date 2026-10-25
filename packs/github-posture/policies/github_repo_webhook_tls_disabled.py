# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-webhook-tls-disabled"
TITLE = "Repository webhooks delivering with TLS verification disabled"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = "A repository webhook with insecure_ssl set delivers repository events over an unverified connection."
REMEDIATION = "Re-enable SSL verification on the webhook and use a destination with a valid certificate."
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["PR.DS-2"]}


def policy(resource):
    application = resource.get("application") or {}
    repo = resource.get("resource") or {}
    if application.get("type") != "github":
        return True
    if repo.get("resource_type") != "repository":
        return True
    settings = resource.get("settings_by_key") or {}
    for key, setting in settings.items():
        if not key.startswith("repo_webhook:"):
            continue
        value = setting.get("value") or {}
        if isinstance(value, dict) and value.get("insecure_ssl") is True:
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
