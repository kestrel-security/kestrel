# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-session-duration-excessive"
TITLE = "Detect Slack accounts whose session lasts longer than 12 hours"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "A long session means a stolen token or an unlocked laptop stays usable for longer, and "
    "a deactivated account keeps working until its session expires. Slack applies session "
    "duration per account, so this is reported per account."
)
REMEDIATION = (
    "Lower the session duration for this member in Slack (Organization settings → Security → "
    "Session duration), or apply a shorter org-wide default."
)
COMPLIANCE = {"nist_csf": ["PR.AC-7"], "soc2": ["CC6.1"]}

MAX_SESSION_HOURS = 12


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "slack":
        return True
    if identity.get("is_disabled"):
        return True
    setting = (resource.get("settings_by_key") or {}).get("session_duration_hours")
    # No row means Slack applied no explicit setting to this account. That is
    # not the same as a long session, so stay quiet rather than guess.
    if setting is None:
        return True
    value = setting.get("value")
    if not isinstance(value, int | float):
        return True
    return value <= MAX_SESSION_HOURS


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    setting = (resource.get("settings_by_key") or {}).get("session_duration_hours") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "max_session_hours": MAX_SESSION_HOURS,
        "application.name": application.get("name"),
    }
