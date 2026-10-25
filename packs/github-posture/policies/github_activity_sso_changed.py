# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-activity-sso-changed"
TITLE = "SAML single sign-on configuration changes"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "SAML SSO was enabled, disabled, or reconfigured, which changes how every member authenticates."
REMEDIATION = "Confirm the change with the actor and verify SSO enforcement is still required for org access."
REQUIRES = ["github:audit_events"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"], "cis": ["5.6"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "github":
        return True
    if event.get("action") != "sso.change":
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
