# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-guest-in-private-channel"
TITLE = "Slack guest is a member of a private or externally shared channel"
SEVERITY = "medium"
RESOURCE_TYPE = "grant"
DESCRIPTION = (
    "A guest account (single- or multi-channel) sits inside a private channel or a Slack Connect "
    "channel. Guests are outside the workspace's identity lifecycle, so their access outlives the "
    "engagement that created it."
)
REMEDIATION = (
    "Confirm the guest still needs the channel; remove them from the channel or set an account "
    "expiration date on the guest in Slack admin -> Manage members."
)
COMPLIANCE = {"custom": ["SLACK-03"], "soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"]}
REQUIRES = ["slack:identity"]


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    channel = resource.get("resource") or {}
    if application.get("type") != "slack":
        return True
    if str(channel.get("resource_type") or "") != "channel":
        return True
    if not identity.get("is_external"):
        return True
    config = channel.get("config") or {}
    sensitive = bool(config.get("is_private")) or bool(config.get("is_external")) or channel.get("visibility") == "private"
    return not sensitive


def evidence(resource):
    identity = resource.get("identity") or {}
    channel = resource.get("resource") or {}
    application = resource.get("application") or {}
    config = channel.get("config") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "resource.name": channel.get("name"),
        "resource.visibility": channel.get("visibility"),
        "resource.is_external": config.get("is_external"),
        "application.name": application.get("name"),
    }
