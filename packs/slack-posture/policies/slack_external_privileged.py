# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-external-privileged"
TITLE = "Detect Slack guest (restricted) identities with Owner or Admin roles"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect Slack guest (restricted) identities with Owner or Admin roles"
REMEDIATION = "Remove privileged workspace roles from guest accounts; guests should never be Owners or Admins."
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}

SLACK_PRIVILEGED_ROLES = ("Admin", "Owner", "Primary Owner")


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "slack":
        return True
    if not identity.get("is_external"):
        return True
    if not any(r in roles for r in SLACK_PRIVILEGED_ROLES):
        return True
    return False


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_external": identity.get("is_external"),
        "application.name": application.get("name"),
    }
