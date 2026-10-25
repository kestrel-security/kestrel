# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-api-token-unused"
TITLE = "Okta API tokens unused for 180+ days"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags Okta API token service identities with no activity in the last 180 days."
REMEDIATION = "Revoke unused API tokens and rotate credentials for automation accounts."
COMPLIANCE = {"custom": ["OKTA-04"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-4"]}

UNUSED_DAYS = 180


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "okta":
        return True
    if identity.get("identity_type") != "service_account":
        return True
    display = str(identity.get("display_name") or "")
    if not display.startswith("API token:"):
        return True
    return within_last_days(identity.get("last_active_at"), UNUSED_DAYS)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "application.name": application.get("name"),
    }
