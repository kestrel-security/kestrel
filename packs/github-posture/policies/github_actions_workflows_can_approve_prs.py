# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-actions-workflows-can-approve-prs"
TITLE = "GitHub orgs where workflows can approve pull requests"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A workflow that can approve pull requests can satisfy its own review requirement, defeating branch protection."
)
REMEDIATION = "Disable 'Allow GitHub Actions to create and approve pull requests' in Organization settings -> Actions."
REQUIRES = ["github:actions_settings"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "can_approve_pull_request_reviews":
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
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
