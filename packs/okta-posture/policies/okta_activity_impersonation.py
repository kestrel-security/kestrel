# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-impersonation"
TITLE = "Okta administrator session impersonation"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Flags Okta System Log events where an administrator initiated or granted "
    "a session impersonation. Impersonation gives an admin access to another "
    "user's session and is a high-privilege action that should always be reviewed."
)
REMEDIATION = (
    "Review impersonation events in Admin Console → Reports → System Log. "
    "Confirm the impersonation was authorized by a legitimate help-desk ticket "
    "or change request. Consider restricting impersonation to break-glass procedures."
)
COMPLIANCE = {
    "custom": ["OKTA-B07"],
    "nist_csf": ["DE.AE-2", "PR.AC-6"],
    "cis": ["5.4"],
    "soc2": ["CC6.3", "CC7.2"],
}
REQUIRES = ["okta:system_log"]


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    action = event.get("action") or ""
    if action != "admin.console":
        return True
    attrs = event.get("attributes") or {}
    okta_event = str(attrs.get("okta_event_type") or "")
    return "impersonation" not in okta_event


def evidence(resource):
    event = resource.get("event") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.okta_event_type": attrs.get("okta_event_type"),
        "event.actor_email": event.get("actor_email"),
        "event.target_email": event.get("target_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
    }
