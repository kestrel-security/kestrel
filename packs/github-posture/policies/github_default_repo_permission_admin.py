# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-default-repo-permission-admin"
TITLE = "GitHub organizations whose default repository permission is admin"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags GitHub organizations whose default repository permission is admin"
REMEDIATION = "Lower the organization default repository permission to read or none; grant admin only via teams."
COMPLIANCE = {"custom": ["GH-08"], "soc2": ["CC6.1"], "cis": ["5.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "default_repository_permission":
        return True
    return setting.get("value") != "admin"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
    }
