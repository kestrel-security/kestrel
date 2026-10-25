# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-api-token-created"
TITLE = "Okta API tokens created in the System Log"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An Okta API token inherits the permissions of the admin who created it, does not expire by "
    "default, and is not covered by MFA. Creating one is a legitimate action and a standard way "
    "to keep access after a password reset, so each should be attributable to a change."
)
REMEDIATION = (
    "Confirm the token was expected. Revoke it in Security -> API -> Tokens if not, and prefer a "
    "scoped OAuth service app over a long-lived SSWS token."
)
COMPLIANCE = {"custom": ["OKTA-06"], "soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["okta:system_log"]


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    if event.get("action") != "api.token.create":
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
