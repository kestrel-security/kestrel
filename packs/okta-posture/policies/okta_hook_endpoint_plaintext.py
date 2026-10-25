# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-hook-endpoint-plaintext"
TITLE = "Detect Okta hooks calling out over plain HTTP"
SEVERITY = "critical"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "An inline hook runs during authentication and can change its outcome; an event hook carries identity"
    " events. Over plain HTTP either can be read or altered in transit."
)
REMEDIATION = "Move the hook endpoint to HTTPS with a valid certificate, or disable the hook."
REQUIRES = ["okta:hooks"]
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["PR.DS-2"], "cis": ["5.6"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    key = str(setting.get("key") or "")
    if not (key.startswith("okta_inline_hook:") or key.startswith("okta_event_hook:")):
        return True
    if str(value.get("status") or "").upper() != "ACTIVE":
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
