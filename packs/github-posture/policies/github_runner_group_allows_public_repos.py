# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-runner-group-allows-public-repos"
TITLE = "Detect self-hosted runner groups reachable from public repositories"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A self-hosted runner reachable from a public repository executes pull-request code from any fork on "
    "your own infrastructure."
)
REMEDIATION = (
    "Set the runner group's 'Allow public repositories' to off, or move public repositories to GitHub-hosted runners."
)
REQUIRES = ["github:actions_settings"]
COMPLIANCE = {"soc2": ["CC6.6", "CC8.1"], "nist_csf": ["PR.AC-5"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("actions_runner_group_public_repos:"):
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
