# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-direct-shared-drive-admin"
TITLE = "Direct (non-group) admin grants on Google Workspace shared drives"
SEVERITY = "medium"
RESOURCE_TYPE = "grant"
DESCRIPTION = "Flags direct (non-group) admin grants on Google Workspace shared drives"
REMEDIATION = "Prefer group-mediated shared-drive organizer grants so access reviews stay centralized."
COMPLIANCE = {"cisa": ["GWS-04"], "soc2": ["CC6.1"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    grant = resource.get("grant") or {}
    if application.get("type") != "google_workspace":
        return True
    if grant.get("granted_via") != "direct":
        return True
    return grant.get("permission_level") != "admin"


def evidence(resource):
    identity = resource.get("identity") or {}
    resource_row = resource.get("resource") or {}
    grant = resource.get("grant") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "resource.name": resource_row.get("name"),
        "grant.granted_via": grant.get("granted_via"),
        "grant.permission_level": grant.get("permission_level"),
    }
