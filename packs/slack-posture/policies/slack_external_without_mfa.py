# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-external-without-mfa"
TITLE = "Detect Slack guest (restricted) identities without two-factor authentication"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect Slack guest (restricted) identities without two-factor authentication"
REMEDIATION = "Require 2FA for guest accounts that retain workspace access, or remove the guest."
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "slack":
        return True
    if not identity.get("is_external"):
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
