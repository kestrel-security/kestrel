# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-threat-detected"
TITLE = "Recent Okta threat or attack events in System Log"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = "Flags recent Okta threat or attack events in System Log"
REMEDIATION = "Investigate the actor in Okta System Log and Identity Threat Protection; revoke sessions if confirmed."
COMPLIANCE = {"custom": ["OKTA-05"], "soc2": ["CC7.2"], "nist_csf": ["DE.CM-1"]}


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    if event.get("action") != "threat.detected":
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
