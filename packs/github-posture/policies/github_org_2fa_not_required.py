# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-org-2fa-not-required"
TITLE = "Detect GitHub organizations that do not require two-factor authentication for members"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Detect GitHub organizations that do not require two-factor authentication for members"
REMEDIATION = "Enable organization-wide two-factor authentication requirement in GitHub organization settings."
COMPLIANCE = {"custom": ["GH-07"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "two_factor_requirement_enabled":
        return True
    return setting.get("value") is not False


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
