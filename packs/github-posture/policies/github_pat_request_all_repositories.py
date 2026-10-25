# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-pat-request-all-repositories"
TITLE = "Detect pending fine-grained PAT requests scoped to every repository"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A member is waiting on approval for a fine-grained personal access token that covers every "
    "repository in the organization, not a named set. Approving it issues one long-lived "
    "credential with the requested permissions across the whole org, and the approval queue is "
    "the only place that decision is ever reviewed."
)
REMEDIATION = (
    "Deny the request and ask for one scoped to the repositories the work actually needs. If "
    "org-wide access is genuinely required, approve it deliberately and set an expiry."
)
REQUIRES = ["github:org_security"]
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "nist_csf": ["PR.AC-4"]}


def policy(resource):
    """True = compliant.

    The sibling of `github-pending-admin-invitation`, and keyed the same way:
    on how much the pending decision would grant, not on how long it has been
    pending. A request for a named set of repositories is the healthy shape and
    stays quiet no matter how many of them there are.
    """
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("pat_request:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    return str(value.get("repository_selection") or "").lower() != "all"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
    return {
        "setting.key": setting.get("key"),
        "request.owner": value.get("owner"),
        "request.created_at": value.get("created_at"),
        "request.repository_selection": value.get("repository_selection"),
        "request.permissions": value.get("permissions"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
