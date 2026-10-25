# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-group-accepts-external-posts"
TITLE = "Google Workspace groups that accept messages from outside the organization"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Anyone on the internet can post to this group's address. Whatever they send is delivered to "
    "every member from an internal-looking group address, which is the shape a phishing message "
    "wants: recipients trust the sender, and the usual external-sender warnings do not apply to "
    "an internal distribution list."
)
REMEDIATION = (
    "Restrict 'Who can post' to group members or to the organization. Support and contact "
    "addresses that genuinely need public mail should be moderated rather than open, so a human "
    "approves what reaches the membership."
)
COMPLIANCE = {"soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"], "custom": ["GWS-13"]}

OPEN_TO_ANYONE = "ANYONE_CAN_POST"


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "group_who_can_post_message":
        return True
    return str(setting.get("value") or "").upper() != OPEN_TO_ANYONE


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
