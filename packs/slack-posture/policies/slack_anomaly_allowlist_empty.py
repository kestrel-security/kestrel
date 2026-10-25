# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-anomaly-allowlist-empty"
TITLE = "Slack Enterprise anomaly allowlist left empty"
SEVERITY = "low"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Flags Enterprise Grid orgs where the Audit Logs anomaly IP/ASN allowlist "
    "is empty. An empty allowlist is informational — configure trusted ranges "
    "only when you have known safe CIDRs/ASNs to suppress false positives."
)
REMEDIATION = (
    "In Slack Enterprise Admin → Security → Anomaly event response, add trusted "
    "CIDRs or ASNs only for known corporate egress. Leaving it empty is valid; "
    "this finding flags that no allowlist has been configured yet."
)
COMPLIANCE = {"soc2": ["CC7.2"], "nist_csf": ["DE.CM-1"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "slack":
        return True
    if setting.get("key") != "anomaly_allowlist_configured":
        return True
    return setting.get("value") is not False


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
