# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-activity-app-installed"
TITLE = "Detect Slack applications installed into the workspace"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An application was installed into the workspace. An installed Slack app holds a long-lived "
    "token against the scopes it asked for, reads the channels it is added to, and keeps working "
    "after the person who installed it leaves. The posture checks see the app once it exists; "
    "this is the moment it arrived, and who brought it in."
)
REMEDIATION = (
    "Confirm the application and its scopes were reviewed. If installation did not go through an "
    "approval, turn on app approval for the workspace so the next one does."
)
COMPLIANCE = {"custom": ["SLACK-12"], "soc2": ["CC6.1", "CC6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    """True = compliant.

    Distinct from `slack-activity-app-scopes-expanded`, which fires when an
    already-installed app asks for more: the two report different moments in
    the same app's life and never the same event.
    """
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "slack":
        return True
    if event.get("action") != "oauth.app.install":
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
        "event.attributes": event.get("attributes"),
        "application.name": application.get("name"),
    }
