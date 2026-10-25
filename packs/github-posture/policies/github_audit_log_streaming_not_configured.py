# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-audit-log-streaming-not-configured"
TITLE = "GitHub organizations without audit log streaming configured"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The organization audit log is not being streamed to an external destination. "
    "Without streaming, audit events are only available via the GitHub UI and API "
    "for a limited retention window. Streaming to a SIEM or log aggregator enables "
    "long-term retention, correlation with other sources, and real-time alerting."
)
REMEDIATION = (
    "Configure audit log streaming in GitHub organization settings → Audit log → "
    "Log streaming. Supported destinations include Amazon S3, Azure Blob Storage, "
    "Google Cloud Storage, Splunk, and Datadog. Requires GitHub Enterprise Cloud."
)
REQUIRES = ["github:audit_events"]
COMPLIANCE = {
    "nist_csf": ["DE.AE-3", "PR.PT-1"],
    "soc2": ["CC7.2"],
    "custom": ["GH-13"],
}

# This policy flags the *absence* of an audit log streaming configuration
# using activity-log evidence: if the connector has never observed an
# `audit_log_streaming.create` event, streaming was never set up. This is
# an approximation — the policy fires only when the audit log is reachable
# (GitHub Enterprise Cloud) and no streaming event appears in the collection
# window. A future connector version may collect streaming config directly.
STREAMING_ACTIONS = frozenset({"audit_log_streaming.create", "audit_log_streaming.update"})


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    if setting.get("key") != "audit_log_streaming_configured":
        return True
    return setting.get("value") is not False


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
