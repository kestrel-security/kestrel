# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-branch-protection-disabled"
TITLE = "Detect branch protection or ruleset removal in the GitHub audit log"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = "Branch protection was removed, overridden, or weakened, so review and status requirements no longer apply."
REMEDIATION = "Restore the protection rule or ruleset and confirm with the actor why it was removed."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.IP-1"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "branch_protection.disable":
        return True
    if not within_last_days(event.get("occurred_at"), 30):
        return True
    return False


def evidence(resource):
    event = resource.get("event") or {}
    attributes = event.get("attributes") or {}
    application = resource.get("application") or {}
    return {
        "event.action": event.get("action"),
        "event.actor_provider_id": event.get("actor_provider_id"),
        "event.actor_login": attributes.get("actor_login"),
        "event.repo": attributes.get("repo"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "application.name": application.get("name"),
    }
