# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-activity-policy-weakening"
TITLE = "Okta policy weakening in System Log"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "Flags Okta System Log events indicating a sign-on, MFA enrollment, or "
    "access policy was modified, deactivated, or deleted. Policy changes that "
    "reduce authentication requirements expand the attack surface."
)
REMEDIATION = (
    "Review the policy change in Admin Console → Security → Authentication Policies "
    "or → Okta Sign-on Policies. Confirm the change was authorized and did not "
    "remove MFA requirements or extend session lifetimes beyond policy."
)
COMPLIANCE = {
    "custom": ["OKTA-B06"],
    "nist_csf": ["PR.AC-5", "DE.AE-2"],
    "cis": ["5.3"],
    "soc2": ["CC6.2", "CC7.2"],
}
REQUIRES = ["okta:system_log"]

POLICY_WEAKENING_ACTIONS = frozenset(
    {
        "policy.change",
    }
)


def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    action = event.get("action") or ""
    if action not in POLICY_WEAKENING_ACTIONS:
        return True
    # Check the okta_event_type for policy-lifecycle destructive operations.
    attrs = event.get("attributes") or {}
    okta_event = str(attrs.get("okta_event_type") or "")
    destructive = "deactivate" in okta_event or "delete" in okta_event
    return not destructive


def evidence(resource):
    event = resource.get("event") or {}
    attrs = event.get("attributes") or {}
    return {
        "event.action": event.get("action"),
        "event.okta_event_type": attrs.get("okta_event_type"),
        "event.actor_email": event.get("actor_email"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
    }
