# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-personal-consent-to-risky-app"
TITLE = "Only one or two users have authorized a third-party app with sensitive Google scopes"
SEVERITY = "medium"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = (
    "An app with mail or Drive scopes that only one or two people have authorized is almost never "
    "a sanctioned integration: it is a personal tool, a trial, or a phishing consent, and it holds "
    "the same token power as an approved app."
)
REMEDIATION = (
    "Ask the users whether the app is still needed; revoke the token from their account page "
    "(Admin console -> Users -> Security -> Connected applications) or block the app for the domain."
)
COMPLIANCE = {"cisa": ["GWS-11"], "soc2": ["CC6.1"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:user_tokens"]
MAX_USERS = 2


def policy(resource):
    application = resource.get("application") or {}
    oauth = resource.get("oauth_application") or {}
    if application.get("type") != "google_workspace":
        return True
    if oauth.get("publisher") == "google":
        return True
    if not (resource.get("sensitive_scope_names") or []):
        return True
    count = resource.get("grant_count")
    if not isinstance(count, int):
        return True
    return count > MAX_USERS


def evidence(resource):
    oauth = resource.get("oauth_application") or {}
    application = resource.get("application") or {}
    return {
        "oauth_application.name": oauth.get("name"),
        "oauth_application.sensitive_scope_names": resource.get("sensitive_scope_names"),
        "oauth_application.grant_count": resource.get("grant_count"),
        "application.name": application.get("name"),
    }
