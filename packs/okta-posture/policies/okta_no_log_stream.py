# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-no-log-stream"
TITLE = "Detect Okta org with no active log stream"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Detect Okta orgs where no active log stream (Splunk, AWS EventBridge, SYSLOG) "
    "is configured. Without an active log stream, security events remain only in "
    "Okta's own System Log and do not reach the security team's SIEM in real time."
)
REMEDIATION = (
    "Configure an active log stream in Admin Console → Reports → Log Streaming "
    "to forward events to your SIEM (Splunk, AWS EventBridge, Datadog, or Syslog)."
)
COMPLIANCE = {
    "custom": ["OKTA-B02"],
    "nist_csf": ["DE.AE-3"],
    "cis": ["8.9"],
    "soc2": ["CC7.2"],
}
REQUIRES = ["okta:log_streams"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "okta":
        return True
    key = setting.get("key") or ""
    if not key.startswith("okta_log_stream:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    # Pass when at least one log stream is active.
    return bool(value.get("is_active"))


def evidence(resource):
    setting = resource.get("setting") or {}
    value = setting.get("value") or {}
    return {
        "log_stream.name": value.get("name"),
        "log_stream.type": value.get("type"),
        "log_stream.status": value.get("status"),
        "log_stream.is_active": value.get("is_active"),
    }
