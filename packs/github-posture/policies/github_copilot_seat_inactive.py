# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-copilot-seat-inactive"
TITLE = "Detect Copilot seats with no recent activity"
SEVERITY = "low"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A GitHub Copilot seat has never been used or has had no activity in the "
    "last 90 days. Inactive seats incur cost without providing value and may "
    "indicate the assignee has left the organization or switched tools. Seats "
    "with null last_activity_at have never been activated."
)
REMEDIATION = (
    "Review the inactive Copilot seat in GitHub organization settings → Copilot → "
    "Access management. Remove the seat assignment for users who are no longer "
    "active or no longer need Copilot access. Consider setting up automatic seat "
    "management if your plan supports it."
)
REQUIRES = ["github:copilot"]
COMPLIANCE = {
    "nist_csf": ["PR.AC-1"],
    "soc2": ["CC6.1"],
}

INACTIVE_DAYS = 90


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = setting.get("key") or ""
    if not key.startswith("copilot_seat:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    last_activity = value.get("last_activity_at")
    if last_activity is None:
        # Never used — this is a finding (seat wasted).
        return False
    return within_last_days(last_activity, INACTIVE_DAYS)


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "copilot_seat.login": value.get("login") if isinstance(value, dict) else None,
        "copilot_seat.last_activity_at": value.get("last_activity_at") if isinstance(value, dict) else None,
        "copilot_seat.last_activity_editor": value.get("last_activity_editor") if isinstance(value, dict) else None,
        "copilot_seat.created_at": value.get("created_at") if isinstance(value, dict) else None,
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
