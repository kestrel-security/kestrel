# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-public-package-from-private-repo"
TITLE = "Detect public GitHub Packages published from private repositories"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "A public GitHub Package is published from a private repository. The repository "
    "is private, meaning its source code is not intended to be public, but the package "
    "it publishes is publicly downloadable. This may expose internal APIs, build "
    "artifacts, or proprietary code to anyone on the internet."
)
REMEDIATION = (
    "Review the package in GitHub Packages and change its visibility to private, "
    "or verify that publishing it publicly is intentional and that the package "
    "does not expose sensitive internal code or proprietary artifacts. To change "
    "visibility, open the package settings and select 'Change visibility'."
)
REQUIRES = ["github:packages"]
COMPLIANCE = {
    "nist_csf": ["PR.AC-3", "PR.DS-5"],
    "soc2": ["CC6.1"],
}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "github":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("org_package:"):
        return True
    value = setting.get("value") or {}
    if not isinstance(value, dict):
        return True
    # A public package from a private repository is the finding.
    return not (str(value.get("visibility") or "").lower() == "public" and value.get("repository_private") is True)


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "package.name": value.get("name") if isinstance(value, dict) else None,
        "package.type": value.get("package_type") if isinstance(value, dict) else None,
        "package.visibility": value.get("visibility") if isinstance(value, dict) else None,
        "package.repository_name": value.get("repository_name") if isinstance(value, dict) else None,
        "package.repository_private": value.get("repository_private") if isinstance(value, dict) else None,
        "application.name": application.get("name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
