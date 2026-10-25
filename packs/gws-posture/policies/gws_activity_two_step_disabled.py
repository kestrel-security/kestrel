# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-activity-two-step-disabled"
TITLE = "Detect 2-Step Verification turned off in the Google Workspace admin audit log"
SEVERITY = "critical"
RESOURCE_TYPE = "event"
DESCRIPTION = (
    "An administrator turned off 2-Step Verification for an account. Workspace is the identity "
    "provider for everything federated through it, so the account's second factor is gone "
    "everywhere at once, and the change is visible only in the admin audit log -- the directory "
    "shows the new state with no record of who made it or when."
)
REMEDIATION = (
    "Re-enroll the account in 2-Step Verification and confirm with the administrator named in the "
    "evidence that the change was intended. If it was not, treat the administrator's own account "
    "as compromised: turning off a second factor is a standard step after an admin takeover."
)
COMPLIANCE = {"custom": ["GWS-14"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    """True = compliant.

    The Workspace counterpart of `okta-activity-mfa-disabled` and
    `github-activity-mfa-disabled`, which have shipped for a while. The action
    was mapped by the connector and nothing read it.
    """
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "google_workspace":
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
