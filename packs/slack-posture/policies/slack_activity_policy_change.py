# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-policy-change"
TITLE = "Detect recent Slack security policy changes in Audit Logs"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Security policy changes (2FA requirements, invite restrictions, channel "
    "management permissions) recorded in Enterprise Audit Logs may weaken the "
    "workspace security posture. Unauthorized policy changes can expand the "
    "attack surface."
)
REMEDIATION = (
    "Review the policy change in Slack Audit Logs. If unauthorized, restore "
    "the previous policy configuration and investigate the actor's account. "
    "Consider restricting who can change workspace security settings."
)
COMPLIANCE = {"nist_csf": ["PR.AC-4", "DE.CM-3"], "soc2": ["CC6.1", "CC7.2"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "policy.change":
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
        "event.attributes.slack_action": (event.get("attributes") or {}).get("slack_action"),
        "application.name": application.get("name"),
    }
