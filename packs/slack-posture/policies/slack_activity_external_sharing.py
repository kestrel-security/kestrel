# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-external-sharing"
TITLE = "Recent Slack external sharing events in Audit Logs"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent Slack Connect channel connections or public file link creation in Audit Logs."
REMEDIATION = "Review the Slack Connect channel or public file link; disconnect or revoke if unexpected."
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "sharing.external":
        return True
    if not within_last_days(event.get("occurred_at"), 30):
        return True
    return False


def evidence(resource):
    event = resource.get("event") or {}
    application = resource.get("application") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_email": event.get("actor_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "application.name": application.get("name"),
    }
