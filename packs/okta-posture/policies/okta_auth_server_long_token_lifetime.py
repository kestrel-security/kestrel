# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-auth-server-long-token-lifetime"
TITLE = "Okta authorization server with excessive access-token lifetime"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Flags custom Okta authorization servers where the access-token lifetime "
    "exceeds 60 minutes. Long-lived tokens remain valid after account disable "
    "or password reset, giving attackers a window to use captured tokens."
)
REMEDIATION = (
    "Reduce the access-token lifetime to 60 minutes or less in Admin Console → "
    "Security → API → Authorization Servers → [server] → Access Policies. "
    "Enable token revocation to invalidate tokens immediately on account disable."
)
COMPLIANCE = {
    "custom": ["OKTA-B03"],
    "nist_csf": ["PR.AC-4"],
    "cis": ["5.1"],
    "soc2": ["CC6.6"],
}
REQUIRES = ["okta:auth_servers"]

MAX_TOKEN_LIFETIME_MINUTES = 60


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    key = setting.get("key") or ""
    if not key.startswith("okta_auth_server:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    # Pass when no lifetime is reported (unknown / not configured).
    return not bool(value.get("token_lifetime_excessive"))


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value") or {}
    return {
        "auth_server.name": value.get("name"),
        "auth_server.max_access_token_lifetime_minutes": value.get("max_access_token_lifetime_minutes"),
        "auth_server.token_lifetime_excessive": value.get("token_lifetime_excessive"),
    }
