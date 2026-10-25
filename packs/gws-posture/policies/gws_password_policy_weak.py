# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-password-policy-weak"
TITLE = "Google Workspace password policy does not enforce strength or minimum length"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that the password policy does not enforce "
    "password strength or a minimum length of 12 characters. Weak passwords increase "
    "credential stuffing and brute-force risk. CISA SCuBA requires password strength "
    "enforcement and a minimum of 12 characters (GWS.COMMONCONTROLS.5.1v1, 5.2v1)."
)
REMEDIATION = (
    "In Google Admin console → Security → Password management, enable "
    "'Enforce strong password' and set the minimum length to at least 12. "
    "Consider using a phishing-resistant MFA method alongside."
)
COMPLIANCE = {"cisa": ["GWS-05"], "cis": ["5.1"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"]}
REQUIRES = ["google_workspace:policy_settings"]

MIN_PASSWORD_LENGTH = 12


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "workspace.password_policy":
        return True
    value = setting.get("value") or {}
    enforced = bool(value.get("enforcePasswordPolicy", False))
    min_length = int(value.get("minimumLength") or 0)
    # Pass only if policy is enforced AND minimum length is adequate.
    return enforced and min_length >= MIN_PASSWORD_LENGTH


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "enforce_password_policy": value.get("enforcePasswordPolicy"),
        "minimum_length": value.get("minimumLength"),
        "required_minimum_length": MIN_PASSWORD_LENGTH,
        "application.name": application.get("name"),
    }
