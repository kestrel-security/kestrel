# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-zone-change"
TITLE = "Okta network zone modification in System Log"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Flags Okta System Log events indicating a network zone was created, "
    "updated, deleted, or deactivated. Network zones gate sign-on policies; "
    "a widened or deleted zone can bypass location-based access controls."
)
REMEDIATION = (
    "Review the zone change in Admin Console → Security → Networks. "
    "Confirm the change was authorized and does not expand admission to "
    "untrusted IP ranges. Audit sign-on policy rules that reference the zone."
)
COMPLIANCE = {
    "custom": ["OKTA-B08"],
    "nist_csf": ["PR.AC-5", "DE.AE-2"],
    "cis": ["5.3"],
    "soc2": ["CC6.2", "CC7.2"],
}
REQUIRES = ["okta:system_log"]


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    attrs = event.get("attributes") or {}
    okta_event = str(attrs.get("okta_event_type") or "")
    return not okta_event.startswith("zone.")


def evidence(resource):
    event = resource.get("event") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.okta_event_type": attrs.get("okta_event_type"),
        "event.actor_email": event.get("actor_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
    }
