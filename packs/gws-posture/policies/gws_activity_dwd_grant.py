# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-activity-dwd-grant"
TITLE = "Google Workspace domain-wide delegation client was authorized"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An admin audit event records that a new domain-wide delegation (DWD) client was "
    "authorized. DWD grants tenant-wide impersonation ability to the OAuth client, so "
    "each new grant should be reviewed for necessity and scope."
)
REMEDIATION = (
    "Confirm the DWD client and its scopes were intentionally added. If not, revoke the "
    "grant in Google Admin console → Security → API controls → Domain-wide delegation. "
    "Review the admin account that authorized the grant for signs of compromise."
)
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:admin_activity"]
WINDOW_DAYS = 30


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "google_workspace":
        return True
    if event.get("action") != "token.grant":
        return True
    attrs = event.get("attributes") or {}
    # token.grant is used for DWD client authorizations (AUTHORIZE_API_CLIENT_ACCESS).
    if attrs.get("gws_event_name") != "AUTHORIZE_API_CLIENT_ACCESS":
        return True
    occurred = event.get("occurred_at")
    # An event with no timestamp is reported rather than assumed to be old.
    if occurred is not None and not within_last_days(occurred, WINDOW_DAYS):
        return True
    return False


def evidence(resource):
    event = resource.get("event") or {}
    application = resource.get("application") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_email": event.get("actor_email"),
        "event.occurred_at": str(event.get("occurred_at") or ""),
        "dwd_client_id": attrs.get("client_id"),
        "dwd_scopes": attrs.get("api_scopes"),
        "application.name": application.get("name"),
    }
