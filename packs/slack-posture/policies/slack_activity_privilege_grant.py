# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-privilege-grant"
TITLE = "Detect recent Slack privileged role grants in Audit Logs"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Detect recent Slack privileged role grants recorded in Enterprise Audit Logs."
REMEDIATION = "Review the privilege grant in Slack Audit Logs; revoke the Owner/Admin or org role if unauthorized."
COMPLIANCE = {"custom": ["SLACK-01"], "soc2": ["CC6.1", "CC6.2"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "privilege.grant":
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
        "event.target_email": event.get("target_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "application.name": application.get("name"),
    }
