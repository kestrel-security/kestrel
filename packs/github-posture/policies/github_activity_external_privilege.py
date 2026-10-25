# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-external-privilege"
TITLE = "Recent privilege grants to external identities"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent privilege grants to external identities"
REMEDIATION = "Remove external privileged access unless explicitly approved."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "privilege.external":
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
