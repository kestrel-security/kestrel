# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-password-policy-weak"
TITLE = "Weak Okta password policy (minimum length below 12)"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags Okta orgs whose password policy minimum length is below 12 characters."
REMEDIATION = "Increase the Okta password policy minimum length to at least 12 and enable complexity requirements."
COMPLIANCE = {"custom": ["OKTA-01"], "soc2": ["CC6.1"], "cis": ["5.2"], "nist_csf": ["PR.AC-1"]}

MIN_PASSWORD_LENGTH = 12


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if setting.get("key") != "password_min_length":
        return True
    value = setting.get("value")
    if value is None:
        return True
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise PolicyDataError(f"password_min_length is not a number: {value!r}") from None
    return length >= MIN_PASSWORD_LENGTH


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
