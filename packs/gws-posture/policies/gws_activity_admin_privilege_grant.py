# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-activity-admin-privilege-grant"
TITLE = "Google Workspace admin privilege granted to a user"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An admin audit event records that administrative privileges were granted to a user "
    "account. Privilege escalation is a key lateral movement step; unexpected admin "
    "grants may indicate insider threat or a compromised admin account."
)
REMEDIATION = (
    "Confirm the grant was authorized with the granting admin. If unauthorized, revoke "
    "the privilege immediately, audit recent activity from the affected account, and "
    "review the granting admin's session for compromise indicators."
)
COMPLIANCE = {"soc2": ["CC6.2"], "nist_csf": ["PR.AC-4", "DE.CM-7"]}
REQUIRES = ["google_workspace:admin_activity"]
WINDOW_DAYS = 30


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "google_workspace":
        return True
    if event.get("action") != "privilege.grant":
        return True
    occurred = event.get("occurred_at")
    # An event with no timestamp is reported rather than assumed to be old.
    if occurred is not None and not within_last_days(occurred, WINDOW_DAYS):
        return True
    # Any privilege grant in the window is a finding.
    return False


def evidence(resource):
    event = resource.get("event") or {}
    application = resource.get("application") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_email": event.get("actor_email"),
        "event.target_email": event.get("target_email"),
        "event.occurred_at": str(event.get("occurred_at") or ""),
        "event.gws_event_name": attrs.get("gws_event_name"),
        "event.role_name": attrs.get("ROLE_NAME"),
        "application.name": application.get("name"),
    }
