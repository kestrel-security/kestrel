# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-workflow-external-sharing"
TITLE = "Slack workflows that share data with external parties"
SEVERITY = "high"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Workflows with external steps enabled or published to the Slack App "
    "Directory can send messages, data, or files outside the organization. "
    "Unreviewed external workflows are a data-exfiltration risk."
)
REMEDIATION = (
    "Review the workflow in Slack → More → Automations. Disable external "
    "steps if not required, or restrict who can trigger it. For published "
    "workflows, review the App Directory listing and remove if unauthorized."
)
COMPLIANCE = {"nist_csf": ["PR.DS-5"], "soc2": ["CC6.3"]}

REQUIRES = ["slack:workflows"]


def policy(resource):
    application = resource.get("application") or {}
    res = resource.get("resource") or {}
    if application.get("type") != "slack":
        return True
    if res.get("resource_type") != "workflow":
        return True
    config = res.get("config") or {}
    return not (res.get("is_external") or config.get("is_external") or config.get("is_published"))


def evidence(resource):
    res = resource.get("resource") or {}
    application = resource.get("application") or {}
    config = res.get("config") or {}
    return {
        "resource.name": res.get("name"),
        "resource.is_external": res.get("is_external"),
        "resource.config.is_published": config.get("is_published"),
        "resource.config.trigger_type": config.get("trigger_type"),
        "resource.config.app_name": config.get("app_name"),
        "application.name": application.get("name"),
    }
