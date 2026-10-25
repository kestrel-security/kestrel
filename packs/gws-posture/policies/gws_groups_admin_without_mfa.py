# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-groups-admin-without-mfa"
TITLE = "Google Workspace Groups Admins not enrolled in 2-Step Verification"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags Google Workspace Groups Admins not enrolled in 2-Step Verification"
REMEDIATION = (
    "Enroll the Groups Admin in 2-Step Verification, or remove the role until MFA is enabled."
    " Groups Admins can manage membership for sensitive groups."
)
COMPLIANCE = {"cisa": ["GWS-06"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "google_workspace":
        return True
    if "Groups Admin" not in roles:
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
