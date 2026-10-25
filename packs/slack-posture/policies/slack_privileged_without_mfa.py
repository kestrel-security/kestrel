# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-privileged-without-mfa"
TITLE = "Slack Primary Owners, Owners, or Admins without two-factor authentication"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags Slack Primary Owners, Owners, or Admins without two-factor authentication"
REMEDIATION = "Require 2FA for the privileged Slack account, or demote the user from Admin/Owner."
COMPLIANCE = {"custom": ["SLACK-01"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}

SLACK_PRIVILEGED_ROLES = ("Admin", "Owner", "Primary Owner")


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "slack":
        return True
    if not any(r in roles for r in SLACK_PRIVILEGED_ROLES):
        return True
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }
