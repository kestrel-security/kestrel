# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-members-can-create-public-repos"
TITLE = "GitHub organizations that allow members to create public repositories"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags GitHub organizations that allow members to create public repositories"
REMEDIATION = "Disable member creation of public repositories; require admins to create public repos intentionally."
COMPLIANCE = {"custom": ["GH-09"], "soc2": ["CC6.1"], "cis": ["5.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "members_can_create_public_repositories":
        return True
    return setting.get("value") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "setting.category": setting.get("category"),
        "application.name": application.get("name"),
        "application.display_name": application.get("display_name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
