# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-app-scopes-expanded"
TITLE = "Recent Slack app scope expansions in Audit Logs"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent Slack OAuth app scope expansions recorded in Enterprise Audit Logs."
REMEDIATION = "Review the app in Slack Admin → Apps; revoke or re-approve scopes that are not required."
COMPLIANCE = {"custom": ["SLACK-10"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "oauth.scope.expand":
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
