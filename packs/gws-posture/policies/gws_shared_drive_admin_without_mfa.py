# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-shared-drive-admin-without-mfa"
TITLE = "Detect Google Workspace identities with shared-drive admin grants that lack 2-Step Verification"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Detect Google Workspace identities with shared-drive admin grants that lack 2-Step Verification"
REMEDIATION = (
    "Require 2-Step Verification for the account,"
    " or remove shared-drive organizer/fileOrganizer grants until MFA is enrolled."
)
COMPLIANCE = {"cisa": ["GWS-07"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "google_workspace":
        return True
    if identity.get("mfa_enabled"):
        return True
    return not has_admin_grant(resource)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }
