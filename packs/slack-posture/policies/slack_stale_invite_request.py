# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-stale-invite-request"
TITLE = "Slack invite requests pending more than 30 days"
SEVERITY = "low"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Invite requests that remain unreviewed for more than 30 days suggest "
    "that the access-approval process is not being followed. Stale requests "
    "can lead to unauthorized access if eventually auto-approved or approved "
    "without the original context."
)
REMEDIATION = (
    "In Slack Admin → Members → Invitations, review and approve or deny all "
    "pending invite requests. Consider enabling automatic reminders for "
    "unreviewed requests."
)
COMPLIANCE = {"nist_csf": ["PR.AC-1"], "soc2": ["CC6.2"]}

REQUIRES = ["slack:invite_requests"]

STALE_THRESHOLD_DAYS = 30


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "slack":
        return True
    setting = (resource.get("settings_by_key") or {}).get("pending_invite_requests")
    if setting is None:
        return True
    # Check raw_source for days_pending when available.
    raw = resource.get("raw_source") or {}
    days_pending = raw.get("days_pending")
    if not isinstance(days_pending, (int, float)):
        return True
    return days_pending <= STALE_THRESHOLD_DAYS


def evidence(resource):
    application = resource.get("application") or {}
    setting = (resource.get("settings_by_key") or {}).get("pending_invite_requests") or {}
    raw = resource.get("raw_source") or {}
    return {
        "setting.pending_invite_requests": setting.get("value"),
        "raw.days_pending": raw.get("days_pending"),
        "raw.email": raw.get("email"),
        "stale_threshold_days": STALE_THRESHOLD_DAYS,
        "application.name": application.get("name"),
    }
