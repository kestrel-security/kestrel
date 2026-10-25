# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-disabled-privileged"
TITLE = "Detect deactivated Slack identities that still hold Owner or Admin roles"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect deactivated Slack identities that still hold Owner or Admin roles"
REMEDIATION = "Remove Owner/Admin roles from deactivated Slack accounts."
COMPLIANCE = {"custom": ["SLACK-02"], "soc2": ["CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-1"]}

SLACK_PRIVILEGED_ROLES = ("Admin", "Owner", "Primary Owner")


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "slack":
        return True
    if not any(r in roles for r in SLACK_PRIVILEGED_ROLES):
        return True
    return not identity.get("is_disabled")


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_disabled": identity.get("is_disabled"),
        "application.name": application.get("name"),
    }
