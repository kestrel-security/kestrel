# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-webhook-created"
TITLE = "Organization webhooks created or reconfigured"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = "An organization webhook now delivers org events to an external destination."
REMEDIATION = "Confirm the destination is expected and that TLS verification is enabled."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["DE.CM-7"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "webhook.create":
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
