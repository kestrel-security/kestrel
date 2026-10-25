# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-app-overpermissioned"
TITLE = "Installed GitHub Apps holding sensitive organization permissions"
SEVERITY = "high"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = (
    "An installed GitHub App holds long-lived org-wide access; write or credential-surface permissions "
    "make it as privileged as an owner."
)
REMEDIATION = "Review the App's permissions and repository selection, reduce it to the minimum it needs, or uninstall it."
REQUIRES = ["github:org_security"]
COMPLIANCE = {"custom": ["GH-05"], "soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-4"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "github":
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
