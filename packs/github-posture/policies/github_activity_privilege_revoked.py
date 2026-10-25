# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-privilege-revoked"
TITLE = "Detect organization admin privileges being removed"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An organization role was reduced. Benign during offboarding, and a signal worth seeing when it is "
    "not. Kestrel could not report this at all before the audit taxonomy read role changes from their "
    "payload."
)
REMEDIATION = "Confirm the change was intended, particularly if the actor and target are the same person."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.2"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "privilege.revoke":
        return True
    if not within_last_days(event.get("occurred_at"), 30):
        return True
    return False


def evidence(resource):
    event = resource.get("event") or {}
    attributes = event.get("attributes") or {}
    application = resource.get("application") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_provider_id": event.get("actor_provider_id"),
        "event.actor_login": attributes.get("actor_login"),
        "event.repo": attributes.get("repo"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "application.name": application.get("name"),
    }
