# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-app-unused"
TITLE = "Unused Slack app installations"
SEVERITY = "medium"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = (
    "Flags Slack apps whose fixture inventory records a null last_used_at. "
    "Live Admin Apps payloads do not include last activity; rows without the "
    "last_used_at key are skipped so Grid apps are not all marked unused."
)
REMEDIATION = "Uninstall or restrict Slack apps that have never been used."
COMPLIANCE = {"custom": ["SLACK-11"], "soc2": ["CC6.3"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "slack":
        return True
    if "last_used_at" not in resource:
        return True
    return resource.get("last_used_at") is not None


def evidence(resource):
    oauth = resource.get("oauth_application") or {}
    application = resource.get("application") or {}
    return {
        "oauth_application.name": oauth.get("name"),
        "oauth_application.publisher": oauth.get("publisher"),
        "oauth_application.last_used_at": resource.get("last_used_at"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
