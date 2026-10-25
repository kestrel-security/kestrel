# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-self-service-registration-enabled"
TITLE = "Okta profile enrollment policies allowing self-service registration"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Self-service registration lets anyone who reaches the sign-in page create an account in the directory."
REMEDIATION = (
    "Disable self-service registration on the profile enrollment policy, or restrict it to an allowed "
    "email domain with admin approval."
)
REQUIRES = ["okta:enrollment_policies"]
COMPLIANCE = {"soc2": ["CC6.2"], "nist_csf": ["PR.AC-1"], "cis": ["5.1"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if not str(setting.get("key") or "").startswith("okta_policy:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict) or value.get("type") != "PROFILE_ENROLLMENT":
        return True
    return value.get("self_service_registration_enabled") is not True


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
