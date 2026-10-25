# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-dormant-admin"
TITLE = "Privileged Slack admins inactive for 90+ days"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags privileged Slack Primary Owners, Owners, or Admins whose last activity is older than 90 days."
REMEDIATION = (
    "Review the dormant admin account in Slack, remove unnecessary Owner/Admin privileges, or confirm continued need."
)
COMPLIANCE = {"custom": ["SLACK-01"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}

SLACK_PRIVILEGED_ROLES = (
    "Primary Owner",
    "Owner",
    "Admin",
    "Org Admin",
    "Org Owner",
    "User Admin",
    "Channel Admin",
    "Role Admin",
)
DORMANT_DAYS = 90
TRUSTED_ACTIVITY_SOURCES = ("login", "audit")


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "slack":
        return True
    if not any(r in roles for r in SLACK_PRIVILEGED_ROLES):
        return True
    # Slack only exposes real sign-in activity through Audit Logs. A profile
    # timestamp is not activity, so without a trustworthy source this policy
    # stays quiet rather than calling every admin dormant.
    if identity.get("last_active_source") not in TRUSTED_ACTIVITY_SOURCES:
        return True
    return within_last_days(identity.get("last_active_at"), DORMANT_DAYS)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "identity.last_active_source": identity.get("last_active_source"),
        "application.name": application.get("name"),
    }
