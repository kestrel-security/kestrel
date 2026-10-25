# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-auth-server-wildcard-scope"
TITLE = "Detect Okta authorization server with wildcard or overly broad scope"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Detect custom Okta authorization servers that expose a wildcard scope (*) "
    "or a scope ending with :*. A wildcard scope grants any caller access to all "
    "resources the server protects, defeating the purpose of scope-based access control."
)
REMEDIATION = (
    "Replace wildcard scopes with specific, named scopes in Admin Console → "
    "Security → API → Authorization Servers → [server] → Scopes. "
    "Review all client applications that use the wildcard scope before removing it."
)
COMPLIANCE = {
    "custom": ["OKTA-B04"],
    "nist_csf": ["PR.AC-4"],
    "cis": ["5.1"],
    "soc2": ["CC6.3"],
}
REQUIRES = ["okta:auth_servers"]


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
    return not bool(value.get("has_wildcard_scope"))


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value") or {}
    return {
        "auth_server.name": value.get("name"),
        "auth_server.has_wildcard_scope": value.get("has_wildcard_scope"),
        "auth_server.scope_count": value.get("scope_count"),
    }
