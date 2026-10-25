# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-ruleset-not-enforced"
TITLE = "Repository rulesets that are configured but not enforcing"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A ruleset set to disabled or evaluate appears in the repository's settings exactly like an "
    "active one, and blocks nothing. Evaluate mode records what would have been rejected; the "
    "push still lands."
)
REMEDIATION = (
    "Set the ruleset's enforcement to Active once its evaluation period is complete, or delete it "
    "so the repository's real protection is what the settings show."
)
REQUIRES = ["github:repo_security"]
COMPLIANCE = {"soc2": ["CC8.1"], "nist_csf": ["PR.IP-1"]}


def policy(resource):
    """True = compliant.

    The per-repository counterpart of `github-org-ruleset-not-enforced`. The
    two cannot double-report: a ruleset belongs to either the organization or
    one repository, and the key prefix says which.
    """
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("repo_ruleset:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    return str(value.get("enforcement") or "").lower() == "active"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "setting.category": setting.get("category"),
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
