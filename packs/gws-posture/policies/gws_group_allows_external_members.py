# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-group-allows-external-members"
TITLE = "Google group accepts members from outside the Workspace domains"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A Google group that allows external members can carry anyone on the internet into every "
    "Drive folder, Calendar, and application the group is granted access to."
)
REMEDIATION = (
    "In Google Groups settings for this group, turn off 'Allow external members' unless the group "
    "exists specifically for partner collaboration, and review its current external members."
)
COMPLIANCE = {"cisa": ["GWS-10"], "soc2": ["CC6.1"], "cis": ["5.2"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["google_workspace:group_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "group_allow_external_members":
        return True
    return setting.get("value") is not True


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
    }
