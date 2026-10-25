# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-actions-default-token-write"
TITLE = "GitHub orgs where workflows get a write-scoped GITHUB_TOKEN by default"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Every workflow in every repository starts with write access to its repository, so one compromised action can push code."
)
REMEDIATION = (
    "Set Organization settings -> Actions -> Workflow permissions to read-only, and grant write per "
    "workflow where it is genuinely needed."
)
REQUIRES = ["github:actions_settings"]
COMPLIANCE = {"soc2": ["CC6.1", "CC8.1"], "nist_csf": ["PR.AC-4"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "default_workflow_permissions":
        return True
    return str(setting.get("value") or "").lower() != "write"


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
