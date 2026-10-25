# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-repo-made-public"
TITLE = "Repositories changed from private to public"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "A repository's visibility changed to public, exposing its full history to anyone."
REMEDIATION = (
    "Confirm the change was intended. If not, make the repository private again and rotate any credential in its history."
)
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"custom": ["GH-03"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "sharing.external":
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
