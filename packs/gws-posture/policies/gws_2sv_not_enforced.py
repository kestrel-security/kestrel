# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-2sv-not-enforced"
TITLE = "Detect Google Workspace accounts without 2-Step Verification enforced"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "An administrator has not enforced 2-Step Verification on this Google Workspace account. "
    "Enrollment is the user's own choice until enforcement makes it mandatory, so an enrolled "
    "but unenforced account can still turn 2-Step Verification back off."
)
REMEDIATION = (
    "Turn on 2-Step Verification enforcement for the account's organizational unit in the "
    "Google Admin console (Security → Authentication → 2-Step Verification)."
)
COMPLIANCE = {"cisa": ["GWS-08"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "google_workspace":
        return True
    # Suspended and archived accounts cannot sign in, so enforcement is moot.
    if identity.get("is_disabled"):
        return True
    setting = (resource.get("settings_by_key") or {}).get("two_step_verification_enforced")
    # No setting row means the directory did not report enforcement for this
    # account. Absence is not evidence of non-enforcement -- stay quiet.
    if setting is None:
        return True
    return setting.get("value") is not False


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    setting = (resource.get("settings_by_key") or {}).get("two_step_verification_enforced") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
