# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-copilot-public-code-suggestions"
TITLE = "GitHub organizations allowing Copilot to suggest public code matches"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "GitHub Copilot is configured to allow suggestions that match publicly available "
    "code. This setting permits the model to output code that is substantially similar "
    "to code in public repositories, which may carry license obligations (GPL, LGPL, "
    "AGPL, SSPL) and increases the risk of introducing copyrighted third-party code "
    "into private repositories without review."
)
REMEDIATION = (
    "In GitHub organization settings → Copilot → Policies, change the "
    "'Suggestions matching public code' setting to 'Block'. This configures Copilot "
    "to filter suggestions that match public repositories, reducing license and "
    "copyright risk."
)
REQUIRES = ["github:copilot"]
COMPLIANCE = {
    "nist_csf": ["PR.IP-1"],
    "soc2": ["CC6.1"],
}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "copilot_public_code_suggestions":
        return True
    # "allow" is the risky state; "block" or None (not configured) passes.
    return str(setting.get("value") or "").lower() != "allow"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
