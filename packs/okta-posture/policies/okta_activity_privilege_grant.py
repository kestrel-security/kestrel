# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-privilege-grant"
TITLE = "Recent Okta privileged role grants in System Log"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent Okta privileged role grants in System Log"
REMEDIATION = "Review the privilege grant in Okta System Log; revoke the admin role if unauthorized."
COMPLIANCE = {"custom": ["OKTA-03"], "soc2": ["CC6.1", "CC6.2"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
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
