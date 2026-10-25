# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-app-bookmark-or-swa"
TITLE = "Okta apps using bookmark or SWA sign-on (no SSO)"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags Okta applications configured with bookmark or browser-plugin sign-on instead of federated SSO."
REMEDIATION = "Migrate the application to SAML or OIDC SSO, or document an approved exception for bookmark/SWA access."
COMPLIANCE = {"custom": ["OKTA-03"], "soc2": ["CC6.1"], "cis": ["6.7"], "nist_csf": ["PR.AC-3"]}

WEAK_SIGN_ON_MODES = ("BOOKMARK", "BROWSER_PLUGIN")


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("okta_app_sign_on_mode:"):
        return True
    value = setting.get("value") or {}
    mode = str(value.get("sign_on_mode") or "").upper()
    if mode not in WEAK_SIGN_ON_MODES:
        return True
    return False


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
