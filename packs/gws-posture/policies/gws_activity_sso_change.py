# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-activity-sso-change"
TITLE = "Google Workspace SSO configuration was changed"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An admin audit event records that the SSO configuration was changed. "
    "Unauthorized SSO changes can redirect authentication to an attacker-controlled "
    "identity provider, enabling account takeover for all federated users."
)
REMEDIATION = (
    "Confirm the change was authorized. Review the SSO configuration in Google Admin console "
    "→ Security → Authentication → SSO with third-party IdP and verify the IdP entity ID "
    "and ACS URL match the expected values. If unauthorized, revert and investigate the "
    "admin account that made the change."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC7.2"], "nist_csf": ["DE.CM-7"]}
REQUIRES = ["google_workspace:admin_activity"]
WINDOW_DAYS = 90


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "google_workspace":
        return True
    if event.get("action") != "sso.change":
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
        "event.gws_event_name": attrs.get("gws_event_name"),
        "event.sso_status": attrs.get("SSO_STATUS"),
        "event.idp_entity_id": attrs.get("IDP_ENTITY_ID"),
        "application.name": application.get("name"),
    }
