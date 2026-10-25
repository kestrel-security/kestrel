# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-sso-change"
TITLE = "Recent Slack SSO configuration changes in Audit Logs"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "SSO configuration changes (pref.sso_setting_changed) recorded in "
    "Enterprise Audit Logs may weaken authentication requirements for the "
    "workspace. Unauthorized SSO changes allow email/password login for "
    "accounts that should be federated."
)
REMEDIATION = (
    "Review the SSO change in Slack Audit Logs. If unauthorized, restore the "
    "SSO configuration and investigate the actor's account. Enforce SSO via "
    "Org Admin → Security → Authentication → Require SSO."
)
COMPLIANCE = {"nist_csf": ["PR.AC-7", "DE.CM-3"], "soc2": ["CC6.1"], "cis": ["6.3"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "sso.change":
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
