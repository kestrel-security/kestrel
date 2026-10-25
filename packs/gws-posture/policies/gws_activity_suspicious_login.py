# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-activity-suspicious-login"
TITLE = "Google flagged a suspicious sign-in or disabled an account for compromise"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Google's own risk engine marked a sign-in as suspicious, or disabled the account after a "
    "leaked password or hijack. The account may already be in someone else's hands."
)
REMEDIATION = (
    "Confirm the sign-in with the user, force a password change and 2-Step Verification re-enrollment, "
    "and review the account's recent Drive and Gmail activity in the Admin console audit logs."
)
COMPLIANCE = {"cisa": ["GWS-01"], "soc2": ["CC7.2"], "nist_csf": ["DE.CM-7"]}
REQUIRES = ["google_workspace:login_activity"]
WINDOW_DAYS = 30


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "google_workspace":
        return True
    if event.get("action") != "threat.detected":
        return True
    return not within_last_days(event.get("occurred_at"), WINDOW_DAYS)


def evidence(resource):
    event = resource.get("event") or {}
    application = resource.get("application") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_email": event.get("actor_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "event.gws_event_name": attrs.get("gws_event_name"),
        "event.ip_address": attrs.get("ip_address"),
        "application.name": application.get("name"),
    }
