# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-group-open-to-anyone"
TITLE = "Google Workspace groups that anyone with a Google account can join"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "This group's membership is open to anyone with a Google account, inside the organization or "
    "not. Joining it delivers everything the group receives -- and in Workspace a group is not "
    "only a mailing list: it can hold Drive permissions, calendar access, and application "
    "assignments, so self-service membership is self-service access."
)
REMEDIATION = (
    "Set 'Who can join' to invited members only, or to anyone in the organization if the group is "
    "meant to be internally self-service. Then review the current membership: anyone who joined "
    "while it was open is still a member after the setting changes."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-3"], "custom": ["GWS-12"]}

# Google's vocabulary. ALL_IN_DOMAIN_CAN_JOIN is self-service for employees,
# which is a deliberate configuration rather than a defect; only the value that
# admits people from outside the organization is reported here.
OPEN_TO_ANYONE = "ANYONE_CAN_JOIN"


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "group_who_can_join":
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
