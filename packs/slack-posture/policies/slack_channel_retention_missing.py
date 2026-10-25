# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-channel-retention-missing"
TITLE = "Slack private or externally shared channels without a custom retention policy"
SEVERITY = "medium"
RESOURCE_TYPE = "resource"
DESCRIPTION = (
    "Private and externally shared channels may contain sensitive information. "
    "Without a custom retention policy these channels inherit the workspace "
    "default, which may be 'keep forever'. Explicit retention limits reduce "
    "exposure in the event of a breach or legal hold."
)
REMEDIATION = (
    "In Slack Admin → Message Retention, set a custom retention policy on "
    "the channel, or apply an org-wide retention policy to all private "
    "channels. Requires Slack Enterprise Grid or Business+ for custom channel "
    "retention."
)
COMPLIANCE = {"nist_csf": ["PR.IP-6"], "soc2": ["CC6.7"]}

REQUIRES = ["slack:channel_retention"]


def policy(resource):
    application = resource.get("application") or {}
    res = resource.get("resource") or {}
    if application.get("type") != "slack":
        return True
    if res.get("resource_type") != "channel":
        return True
    config = res.get("config") or {}
    if not (config.get("is_private") or res.get("is_external")):
        return True
    # A retention setting attached to this channel passes the check.
    retention = (resource.get("settings_by_key") or {}).get("retention_days")
    return retention is not None


def evidence(resource):
    res = resource.get("resource") or {}
    application = resource.get("application") or {}
    config = res.get("config") or {}
    retention = (resource.get("settings_by_key") or {}).get("retention_days") or {}
    return {
        "resource.name": res.get("name"),
        "resource.is_external": res.get("is_external"),
        "resource.config.is_private": config.get("is_private"),
        "resource.config.member_count": config.get("member_count"),
        "setting.retention_days": retention.get("value"),
        "application.name": application.get("name"),
    }
