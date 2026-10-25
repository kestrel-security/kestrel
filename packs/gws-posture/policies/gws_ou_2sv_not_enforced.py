# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-ou-2sv-not-enforced"
TITLE = "Google Workspace OU does not enforce 2-Step Verification (Policy API)"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that 2-Step Verification is not enforced in "
    "this organizational unit. Until enforcement is enabled users can turn 2SV off or "
    "never enroll, regardless of the per-account `isEnforcedIn2Sv` directory flag."
)
REMEDIATION = (
    "In Google Admin console → Security → Authentication → 2-Step Verification, set "
    "'Enforcement' to 'On' for the affected organizational unit. Grace-period settings "
    "are separate (see gws-ou-2sv-long-grace)."
)
COMPLIANCE = {"cisa": ["GWS-01"], "cis": ["1.1"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "security.two_step_verification_enforcement":
        return True
    value = setting.get("value") or {}
    # ENFORCED means the policy fires only when NOT_ENFORCED.
    return value.get("enforcementMode", "NOT_ENFORCED") == "ENFORCED"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
    }
