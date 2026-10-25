# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-actions-all-third-party-allowed"
TITLE = "Detect GitHub orgs that allow any third-party Action to run"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Allowing all actions lets any third-party action, including one that changes under a mutable tag, "
    "run with repository credentials."
)
REMEDIATION = (
    "Restrict to local-only or an explicit allow list in Organization settings -> Actions, and pin "
    "actions to a full commit SHA."
)
REQUIRES = ["github:actions_settings"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.AC-4"], "cis": ["6.8"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "allowed_actions":
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
