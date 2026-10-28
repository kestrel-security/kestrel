# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-privilege-granted-to-disabled-idp-user"
TITLE = "Privilege granted in an application to a person the identity provider has disabled"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An audit-log event shows a privileged role or admin permission being granted to an "
    "account whose identity-provider account is disabled. Either someone is re-arming a "
    "departed person's local account, or the grant is to an account that should not exist. "
    "The application's own log cannot know the person has left."
)
REMEDIATION = (
    "Revoke the grant, disable the account, and review who made the change and why. Add "
    "identity-provider status to the approval step for privileged grants."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-10"]}

GRANT_ACTIONS = ("privilege.grant",)
LOOKBACK_DAYS = 30


def policy(resource):
    """True = compliant / ignore; False opens a finding on the event."""
    event = resource.get("event") or {}
    if event.get("action") not in GRANT_ACTIONS:
        return True
    if not within_last_days(event.get("occurred_at"), LOOKBACK_DAYS):
        return True
    target = event.get("target") or {}
    if not target:
        return True
    return target.get("cluster_idp_status") != "disabled"


def evidence(resource):
    event = resource.get("event") or {}
    target = event.get("target") or {}
    application = resource.get("application") or {}
    return {
        "event.action": event.get("action"),
        "event.occurred_at": event.get("occurred_at"),
        "event.summary": event.get("summary"),
        "event.actor_email": event.get("actor_email"),
        "target.email": target.get("email"),
        "target.display_name": target.get("display_name"),
        "target.cluster_idp_status": target.get("cluster_idp_status"),
        "application.name": application.get("name"),
    }
