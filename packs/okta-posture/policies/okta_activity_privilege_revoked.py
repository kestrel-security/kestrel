# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-privilege-revoked"
TITLE = "Detect Okta privileged role revocations in the System Log"
SEVERITY = "medium"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "A privileged Okta role was removed from an account. Usually routine offboarding, but an "
    "unexpected revocation is worth seeing: it is also how an attacker removes a rival admin, "
    "and it is the half of the privilege story a grant-only feed leaves out."
)
REMEDIATION = "Confirm the revocation was intended; restore the role in Okta if it was not."
COMPLIANCE = {"custom": ["OKTA-07"], "soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["okta:system_log"]


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    if event.get("action") != "privilege.revoke":
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
        "event.occurred_at": event.get("occurred_at"),
        "event.okta_event_type": (event.get("attributes") or {}).get("okta_event_type"),
        "event.summary": event.get("summary"),
        "application.name": application.get("name"),
    }
