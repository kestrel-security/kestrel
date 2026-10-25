# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-app-installed"
TITLE = "Detect newly installed GitHub Apps"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = "A GitHub App was installed on the organization, granting it long-lived access under its permission set."
REMEDIATION = "Review the App's permissions and repository selection; uninstall it if it was not expected."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"custom": ["GH-05"], "soc2": ["CC6.3"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "oauth.app.install":
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
