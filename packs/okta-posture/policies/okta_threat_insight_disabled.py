# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-threat-insight-disabled"
TITLE = "Okta orgs with Threat Insight disabled"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Flags Okta organizations where Threat Insight is disabled. Okta Security "
    "best practices and CISA SCuBA-style guidance expect Threat Insight (or "
    "equivalent threat detection) to be enabled for the org."
)
REMEDIATION = (
    "In Okta Admin Console, enable Threat Insight under Security → Threat Insight "
    "(or Security → General). Prefer blocking or auditing suspicious IPs rather "
    "than action=none."
)
COMPLIANCE = {
    "custom": ["OKTA-05"],
    "soc2": ["CC7.2"],
    "nist_csf": ["DE.CM-1"],
}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if setting.get("key") != "threat_insight_enabled":
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
    }
