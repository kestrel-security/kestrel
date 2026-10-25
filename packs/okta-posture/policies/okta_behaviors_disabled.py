# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-behaviors-disabled"
TITLE = "Detect disabled Okta behavioral detection"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Detect Okta orgs where behavioral detection rules (anomalousLocation, "
    "anomalousDevice, anomalousIP) are inactive or not evaluating on sign-in. "
    "Disabled behaviors do not feed adaptive authentication signals."
)
REMEDIATION = (
    "Enable behavioral detection rules in Admin Console → Security → Behavior Detection "
    "and set evaluateOnSignIn to true. Combine with ThreatInsight for full risk coverage."
)
COMPLIANCE = {
    "custom": ["OKTA-B01"],
    "nist_csf": ["DE.CM-7"],
    "cis": ["8.11"],
    "soc2": ["CC6.7"],
}
REQUIRES = ["okta:behaviors"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    key = setting.get("key") or ""
    if not key.startswith("okta_behavior:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    # Pass if the behavior is active and evaluating on sign-in.
    return bool(value.get("effective"))


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value") or {}
    return {
        "behavior.name": value.get("name"),
        "behavior.status": value.get("status"),
        "behavior.evaluate_on_sign_in": value.get("evaluate_on_sign_in"),
        "behavior.effective": value.get("effective"),
    }
