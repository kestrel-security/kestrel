# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-external-channel-unrestricted"
TITLE = "Detect externally shared Slack channels"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Detect Slack channels that are externally shared via Slack Connect."
REMEDIATION = (
    "Review the shared channel membership and IdP group restrictions; disconnect external orgs that should not have access."
)
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.1", "CC6.3"], "nist_csf": ["PR.AC-3"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "slack":
        return True
    if setting.get("key") != "external_shared_channel":
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
