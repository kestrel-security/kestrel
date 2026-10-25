# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-password-allows-username"
TITLE = "Detect an Okta password policy that permits the username in the password"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The active Okta password policy does not exclude the user's own name from their password. "
    "Username-derived passwords are the first thing credential-stuffing and spraying tools try."
)
REMEDIATION = (
    "Enable 'Do not allow parts of the username' on the Okta password policy (Security -> Authentication -> Password)."
)
# NIST SP 800-63B discourages composition rules (symbols, mixed case) and asks
# instead that passwords be screened against context-specific words -- the
# username being the canonical example. This checks the screening, not the
# composition, which is why there is no companion "requires a symbol" policy.
COMPLIANCE = {"custom": ["OKTA-09"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"]}
REQUIRES = ["okta:password_policies"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    if setting.get("key") != "password_complexity":
        return True
    value = setting.get("value")
    if not isinstance(value, dict):
        return True
    excluded = value.get("excludeUsername")
    if excluded is None:
        return True
    return bool(excluded)


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
    return {
        "setting.key": setting.get("key"),
        "password.exclude_username": value.get("excludeUsername"),
        "password.min_length": value.get("minLength"),
        "application.name": application.get("name"),
    }
