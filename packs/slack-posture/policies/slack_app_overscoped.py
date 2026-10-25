# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-app-overscoped"
TITLE = "Slack apps with sensitive OAuth scopes"
SEVERITY = "high"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = "Flags installed Slack apps that hold sensitive bot or user scopes."
REMEDIATION = "Remove unused sensitive scopes, restrict the app, or uninstall it from the workspace."
COMPLIANCE = {"custom": ["SLACK-10"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "slack":
        return True
    sensitive = resource.get("sensitive_scope_names") or []
    return not sensitive


def evidence(resource):
    oauth = resource.get("oauth_application") or {}
    application = resource.get("application") or {}
    return {
        "oauth_application.name": oauth.get("name"),
        "oauth_application.publisher": oauth.get("publisher"),
        "oauth_application.sensitive_scope_names": resource.get("sensitive_scope_names"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
