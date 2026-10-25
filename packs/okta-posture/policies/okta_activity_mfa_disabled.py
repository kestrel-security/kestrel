# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-mfa-disabled"
TITLE = "Recent Okta MFA factor deactivation in System Log"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent Okta MFA factor deactivation in System Log"
REMEDIATION = "Re-enable MFA for the affected identity and investigate who deactivated the factor."
COMPLIANCE = {"custom": ["OKTA-04"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    if event.get("action") != "mfa.disable":
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
