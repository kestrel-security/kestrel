# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-session-too-long"
TITLE = "Google Workspace session length exceeds 12 hours without re-authentication"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports a session re-authentication interval of more "
    "than 12 hours. Long sessions increase the window for session hijacking after "
    "a user's workstation is left unattended or a token is stolen. CISA SCuBA requires "
    "re-authentication after no more than 12 hours (GWS.COMMONCONTROLS.4.1v1)."
)
REMEDIATION = "In Google Admin console → Security → Google session control, set the session length to 12 hours or fewer."
COMPLIANCE = {"cisa": ["GWS-04"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]

MAX_SESSION_HOURS = 12


def duration_hours(duration):
    """Duration in hours, from ISO 8601 `PT{n}H` or protobuf-JSON `{seconds}s`.

    A missing value means 0. Any other format raises: reading an unrecognized
    value (`P1D`, `PT90M`) as 0 hours would pass every tenant whatever its
    setting.
    """
    text = str(duration or "PT0H").strip()
    try:
        if text.startswith("PT") and text.endswith("H"):
            return float(text[2:-1])
        if text.endswith("s"):
            return float(text[:-1]) / 3600
    except ValueError:
        pass
    raise PolicyDataError(f"unrecognized session duration {duration!r}")


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "workspace.session.reauth_settings":
        return True
    value = setting.get("value") or {}
    session_length = value.get("sessionLength") or value.get("maxInactivity") or "PT0H"
    return duration_hours(session_length) <= MAX_SESSION_HOURS


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    session_length = value.get("sessionLength") or value.get("maxInactivity") or "PT0H"
    return {
        "setting.key": setting.get("key"),
        "session_length": session_length,
        "session_hours": duration_hours(session_length),
        "max_allowed_hours": MAX_SESSION_HOURS,
        "application.name": application.get("name"),
    }
