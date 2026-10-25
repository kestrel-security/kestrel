# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-config-change"
TITLE = "Recent Slack workspace configuration changes in Audit Logs"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Workspace configuration changes (pref_* events, channel management "
    "changes) recorded in Enterprise Audit Logs indicate that security-relevant "
    "settings may have changed. Review these events to confirm the change was "
    "authorized."
)
REMEDIATION = (
    "Review the configuration change in Slack Audit Logs. If unauthorized, "
    "revert the setting change and investigate the actor's account."
)
COMPLIANCE = {"nist_csf": ["DE.CM-3"], "soc2": ["CC7.2"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "config.change":
        return True
    if not within_last_days(event.get("occurred_at"), 14):
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
        "event.attributes.slack_action": (event.get("attributes") or {}).get("slack_action"),
        "application.name": application.get("name"),
    }
