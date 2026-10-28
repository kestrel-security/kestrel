# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-privilege-granted-to-disabled-idp-user"
TITLE = "Privilege granted in an application to a person the identity provider has disabled"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An audit-log event shows a privileged role or admin permission being granted to an "
    "account after the person's identity-provider account was disabled. Either someone is "
    "re-arming a departed person's local account, or the grant is to an account that should "
    "not exist. The application's own log cannot know the person has left. A grant made before "
    "the person was offboarded is not a finding; when the identity provider did not record when "
    "it disabled the account, the event is not assessable and passes."
)
REMEDIATION = (
    "Revoke the grant, disable the account, and review who made the change and why. Add "
    "identity-provider status to the approval step for privileged grants."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-10"]}
REQUIRES = ["identity:disabled_at"]

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
    if target.get("cluster_idp_status") != "disabled":
        return True
    disabled_at = parse_timestamp(target.get("cluster_idp_disabled_at"))
    if disabled_at is None:
        return True  # not assessable: no record of when offboarding happened
    occurred_at = parse_timestamp(event.get("occurred_at"))
    if occurred_at is None:
        return True
    return occurred_at < disabled_at


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
        "target.cluster_idp_disabled_at": target.get("cluster_idp_disabled_at"),
        "application.name": application.get("name"),
    }
