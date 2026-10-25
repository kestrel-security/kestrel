# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-connect-org-connected"
TITLE = "Slack Connect organizations connected to the workspace"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags external organizations connected via Slack Connect (shadow collaboration surface)."
REMEDIATION = "Review Slack Connect connections in Admin; disconnect organizations that are no longer needed."
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "slack":
        return True
    if setting.get("key") != "slack_connect_org_connected":
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
