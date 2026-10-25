# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-session-never-expires"
TITLE = "Detect Okta policies with an active rule that never expires a session"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Okta encodes an unlimited session lifetime as 0 minutes, so a policy that appears to have a timeout "
    "may have none, and a stolen session cookie stays valid indefinitely."
)
REMEDIATION = "Set a maximum session lifetime and idle timeout on every active rule of the global session policy."
REQUIRES = ["okta:session_policies"]
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"], "cis": ["5.6"]}


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
    return value.get("any_rule_unlimited_session") is not True


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
