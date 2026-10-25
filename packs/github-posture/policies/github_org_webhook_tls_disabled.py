# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-org-webhook-tls-disabled"
TITLE = "Organization webhooks delivering with TLS verification disabled"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A webhook with insecure_ssl set delivers organization events over a connection that is not verified,"
    " exposing payloads to interception."
)
REMEDIATION = "Re-enable SSL verification on the webhook, and use a destination with a valid certificate."
REQUIRES = ["github:org_security"]
COMPLIANCE = {"soc2": ["CC6.7"], "nist_csf": ["PR.DS-2"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("org_webhook:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    return value.get("insecure_ssl") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "setting.category": setting.get("category"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
