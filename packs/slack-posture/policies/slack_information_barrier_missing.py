# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-information-barrier-missing"
TITLE = "Detect Slack Enterprise orgs without information barriers configured"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Information barriers in Slack Enterprise Grid prevent communication "
    "between defined groups (e.g., legal and trading, HR and employees). "
    "Organizations subject to regulatory requirements (FINRA, SEC, HIPAA) "
    "typically need barriers to avoid conflicts of interest or data leakage."
)
REMEDIATION = (
    "In Slack Org Admin → Security → Information Barriers, create barriers "
    "between groups that must not communicate (e.g., Trading and Research). "
    "This requires Slack Enterprise Grid."
)
COMPLIANCE = {"nist_csf": ["PR.AC-4"], "soc2": ["CC6.3"]}

REQUIRES = ["slack:information_barriers"]


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "slack":
        return True
    setting = (resource.get("settings_by_key") or {}).get("information_barrier_configured")
    # No row means either no barriers or the scope is unavailable; stay quiet
    # when the data was never collected.
    if setting is None:
        return True
    return bool(setting.get("value"))


def evidence(resource):
    application = resource.get("application") or {}
    setting = (resource.get("settings_by_key") or {}).get("information_barrier_configured") or {}
    return {
        "setting.information_barrier_configured": setting.get("value"),
        "application.name": application.get("name"),
        "remediation_hint": "Create information barriers in Slack Org Admin → Security.",
    }
