# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-idp-auto-provisions-users"
TITLE = "Detect inbound identity providers that create accounts automatically"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "With JIT provisioning, a successful assertion from this provider creates an Okta account that did "
    "not exist before, so whoever operates it can add users to the org."
)
REMEDIATION = (
    "Set provisioning to manual or disabled unless the provider is fully trusted, and constrain which users it may assert."
)
REQUIRES = ["okta:identity_providers"]
COMPLIANCE = {"soc2": ["CC6.2"], "nist_csf": ["PR.AC-1"], "cis": ["5.1"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    if not str(setting.get("key") or "").startswith("okta_identity_provider:"):
        return True
    if str(value.get("status") or "").upper() != "ACTIVE":
        return True
    return value.get("auto_provisions_users") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value")
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.label": setting.get("label"),
        "setting.value": value,
        "application.name": application.get("name"),
    }
