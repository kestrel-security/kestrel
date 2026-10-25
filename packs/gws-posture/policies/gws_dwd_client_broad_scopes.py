# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-dwd-client-broad-scopes"
TITLE = "Google Workspace domain-wide delegation client holds sensitive scopes"
SEVERITY = "high"
RESOURCE_TYPE = "oauth_application"
DESCRIPTION = (
    "A domain-wide delegation (DWD) OAuth client reconstructed from admin audit holds one "
    "or more sensitive scopes (admin directory, Gmail, Drive, Contacts, etc.). DWD clients "
    "act as any user in the domain without per-user consent, so a client with broad scopes "
    "is a significant lateral movement and exfiltration risk if compromised."
)
REMEDIATION = (
    "In Google Admin console → Security → Access and data control → API controls → "
    "Domain-wide delegation, review the client. Remove the grant if the integration does "
    "not require tenant-wide access, or reduce its scopes to the minimum needed. "
    "Revocations appear in the admin audit log (REVOKE_API_CLIENT_ACCESS)."
)
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:dwd_clients"]


def policy(resource):
    application = resource.get("application") or {}
    oauth_app = resource.get("oauth_application") or {}
    if application.get("type") != "google_workspace":
        return True
    if not oauth_app.get("dwd_client"):
        return True
    # Revoked clients are past-tense: only flag active ones.
    if oauth_app.get("revoked"):
        return True
    return not bool(oauth_app.get("has_sensitive_scopes"))


def evidence(resource):
    oauth_app = resource.get("oauth_application") or {}
    application = resource.get("application") or {}
    return {
        "client_id": oauth_app.get("client_id"),
        "dwd_client": oauth_app.get("dwd_client"),
        "has_sensitive_scopes": oauth_app.get("has_sensitive_scopes"),
        "revoked": oauth_app.get("revoked"),
        "last_changed_by": oauth_app.get("last_changed_by"),
        "last_changed_at": oauth_app.get("last_changed_at"),
        "application.name": application.get("name"),
    }
