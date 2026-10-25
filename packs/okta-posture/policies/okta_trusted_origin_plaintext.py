# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-trusted-origin-plaintext"
TITLE = "Detect Okta trusted origins served over plain HTTP"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A trusted origin can receive a redirect carrying a token. Over plain HTTP that token travels in "
    "cleartext and can be read off the wire."
)
REMEDIATION = "Move the origin to HTTPS, or remove it if the application no longer exists."
REQUIRES = ["okta:trusted_origins"]
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["PR.DS-2"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    if not str(setting.get("key") or "").startswith("okta_trusted_origin:"):
        return True
    return value.get("insecure_scheme") is not True


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
