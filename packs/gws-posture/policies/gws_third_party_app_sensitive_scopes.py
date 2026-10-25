# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-third-party-app-sensitive-scopes"
TITLE = "Third-party app holds Gmail, Drive, Admin, or Cloud scopes on Google Workspace accounts"
SEVERITY = "high"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = (
    "A third-party OAuth application that users have authorized with mail, Drive, contacts, "
    "Admin SDK, or Cloud Platform scopes can read or exfiltrate that data with every user's "
    "consent until the token is revoked."
)
REMEDIATION = (
    "Review the application in Admin console -> Security -> API controls -> App access control. "
    "Block or limit it, or mark it trusted with a documented owner; then revoke the existing user "
    "tokens so users re-consent under the new policy."
)
COMPLIANCE = {"cisa": ["GWS-11"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:user_tokens"]


def policy(resource):
    application = resource.get("application") or {}
    oauth = resource.get("oauth_application") or {}
    if application.get("type") != "google_workspace":
        return True
    if oauth.get("publisher") == "google":
        return True
    return not (resource.get("sensitive_scope_names") or [])


def evidence(resource):
    oauth = resource.get("oauth_application") or {}
    application = resource.get("application") or {}
    return {
        "oauth_application.name": oauth.get("name"),
        "oauth_application.publisher": oauth.get("publisher"),
        "oauth_application.sensitive_scope_names": resource.get("sensitive_scope_names"),
        "oauth_application.grant_count": resource.get("grant_count"),
        "application.name": application.get("name"),
    }
