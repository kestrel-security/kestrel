# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-actions-secret-visible-to-all-repos"
TITLE = "Organization Actions secrets readable by every repository"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "An org secret with visibility 'all' can be read by a workflow in any repository, including one a new"
    " member just created."
)
REMEDIATION = "Set the secret's visibility to selected repositories, or move it to the repositories that need it."
REQUIRES = ["github:actions_settings"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-4"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("actions_secret_visibility:"):
        return True
    return str(setting.get("value") or "").lower() != "all"


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
