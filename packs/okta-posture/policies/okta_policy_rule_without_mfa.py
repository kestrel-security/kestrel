# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-policy-rule-without-mfa"
TITLE = "Detect Okta policies with an active rule that requires no second factor"
SEVERITY = "critical"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "An active rule that does not require a factor is the rule an attacker will match, whatever the other rules demand."
)
REMEDIATION = "Require a factor on every active rule, or deactivate the rule that does not."
REQUIRES = ["okta:signon_policies"]
COMPLIANCE = {"custom": ["OKTA-01"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"], "cis": ["6.3"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if not str(setting.get("key") or "").startswith("okta_policy:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    return value.get("any_rule_without_mfa") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value")
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.label": setting.get("label"),
        "setting.value": value if not isinstance(value, dict) else {k: v for k, v in value.items() if k != "rules"},
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
