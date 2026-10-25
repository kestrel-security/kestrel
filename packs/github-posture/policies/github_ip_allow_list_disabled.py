# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-ip-allow-list-disabled"
TITLE = "GitHub organizations with IP allow list disabled"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The GitHub organization IP allow list is disabled. When enabled, only "
    "requests from listed IP addresses or CIDR ranges can access the organization "
    "via the API, webhooks, and Actions. Disabling it exposes organization resources "
    "to requests from any IP address."
)
REMEDIATION = (
    "Enable the IP allow list in GitHub organization settings → Security → IP allow list "
    "and add your corporate egress IP ranges or CIDR blocks. Ensure at least one active "
    "entry covers your runners and CI/CD infrastructure before enabling."
)
REQUIRES = ["github:ip_allow_list"]
COMPLIANCE = {
    "cis": ["6.1"],
    "nist_csf": ["PR.AC-3"],
    "soc2": ["CC6.6"],
    "custom": ["GH-01"],
}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "ip_allow_list_enabled":
        return True
    # None means the feature is not available (not Enterprise Cloud); skip.
    if setting.get("value") is None:
        return True
    return setting.get("value") is not False


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
