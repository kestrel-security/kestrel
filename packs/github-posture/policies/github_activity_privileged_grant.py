# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-privileged-grant"
TITLE = "Recent privileged grant activity in GitHub audit log"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent privileged grant activity in GitHub audit log"
REMEDIATION = "Review the privileged grant in GitHub audit log; revoke if unauthorized."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.1", "CC6.2"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
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
