# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-guest-created"
TITLE = "Guest accounts created in the Slack audit log"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "A guest account was created. Guests are the intended way to work with people outside the "
    "company, and they are also the least reviewed account in most workspaces: a single-channel "
    "guest can be invited by a workspace admin without a request, keeps access until someone "
    "notices, and does not appear in an identity-provider offboarding run because they were "
    "never in the directory."
)
REMEDIATION = (
    "Confirm the guest is expected and has an owner and an end date. Slack does not expire guest "
    "accounts on its own, so an unowned guest stays until it is deactivated by hand."
)
COMPLIANCE = {"custom": ["SLACK-05"], "soc2": ["CC6.2"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "identity.guest":
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
