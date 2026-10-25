# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-deploy-key-created"
TITLE = "Deploy keys added to repositories"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "A deploy key grants repository access outside the member and team model, and survives the person who added it."
)
REMEDIATION = "Confirm the key is expected, scoped read-only where possible, and owned by a named team."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "deploy_key.create":
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
