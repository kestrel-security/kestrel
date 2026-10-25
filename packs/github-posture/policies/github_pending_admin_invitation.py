# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-pending-admin-invitation"
TITLE = "Detect unaccepted GitHub organization invitations that grant admin"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A pending invitation to the admin role becomes org ownership the moment it is accepted, with no further review."
)
REMEDIATION = "Cancel the invitation if it is not expected, or reissue it at the member role and grant admin deliberately."
REQUIRES = ["github:org_security"]
COMPLIANCE = {"soc2": ["CC6.2"], "nist_csf": ["PR.AC-1"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("pending_invitation:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    return str(value.get("role") or "").lower() != "admin"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "setting.category": setting.get("category"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
