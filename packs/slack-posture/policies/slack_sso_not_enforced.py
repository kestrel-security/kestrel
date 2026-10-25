# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-sso-not-enforced"
TITLE = "Slack Enterprise orgs where SSO bypass is allowed"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "When admin.auth.policy.getEntities returns entities that may bypass "
    "mandatory SSO (email/password authentication allowed), phishing and "
    "credential-stuffing attacks can succeed even if SSO is configured. "
    "Enforcement requires zero bypass entities."
)
REMEDIATION = (
    "In Slack Org Admin → Security → Authentication, set 'Require SSO' with "
    "no bypass users or groups. Remove any existing email/password bypass "
    "entities listed in admin.auth.policy.getEntities."
)
COMPLIANCE = {"nist_csf": ["PR.AC-7"], "soc2": ["CC6.1"], "cis": ["6.3"]}

REQUIRES = ["slack:sso_policy"]


def policy(resource):
    application = resource.get("application") or {}
    if application.get("type") != "slack":
        return True
    setting = (resource.get("settings_by_key") or {}).get("sso_bypass_count")
    if setting is None:
        # SSO policy not collected (non-Grid or missing scope) — stay quiet.
        return True
    value = setting.get("value")
    if not isinstance(value, (int, float)):
        return True
    return value == 0


def evidence(resource):
    application = resource.get("application") or {}
    setting = (resource.get("settings_by_key") or {}).get("sso_bypass_count") or {}
    policy_type = (resource.get("settings_by_key") or {}).get("sso_policy_type") or {}
    return {
        "setting.sso_bypass_count": setting.get("value"),
        "setting.sso_policy_type": policy_type.get("value"),
        "application.name": application.get("name"),
    }
