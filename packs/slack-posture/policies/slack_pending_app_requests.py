# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-pending-app-requests"
TITLE = "Unresolved Slack app install requests"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = "Flags pending Slack app install requests that have not been approved or denied."
REMEDIATION = "In Slack Admin → Apps → Requests, approve only required apps or deny unused requests."
COMPLIANCE = {"custom": ["SLACK-10"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "slack":
        return True
    if setting.get("key") != "pending_app_requests":
        return True
    value = setting.get("value")
    if value is None:
        return True
    try:
        count = int(value)
    except (TypeError, ValueError):
        raise PolicyDataError(f"pending_app_requests is not a count: {value!r}") from None
    return count <= 0


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
