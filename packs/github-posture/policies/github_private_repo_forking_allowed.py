# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-private-repo-forking-allowed"
TITLE = "GitHub organizations that allow private repositories to be forked"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Any member can fork a private or internal repository into a namespace the organization does "
    "not govern. The fork keeps the code but leaves behind the branch protection, the rulesets, "
    "the secret scanning, and the audit trail -- and it survives the member losing access to the "
    "original."
)
REMEDIATION = (
    "Turn off 'Allow forking of private repositories' in the organization's member privileges, or "
    "restrict it to the specific repositories that need it. Existing forks are not removed by the "
    "setting change and have to be found and deleted separately."
)
REQUIRES = ["github:org_settings"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "members_can_fork_private_repositories":
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
