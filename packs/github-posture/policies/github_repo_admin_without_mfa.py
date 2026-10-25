# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-repo-admin-without-mfa"
TITLE = "GitHub identities with repository admin grants that do not have MFA enabled"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags GitHub identities with repository admin grants that do not have MFA enabled"
REMEDIATION = "Require MFA for the account, or remove repository admin grants until MFA is enrolled."
COMPLIANCE = {"custom": ["GH-05"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "github":
        return True
    # Only an explicit False is a violation -- None means the connector could
    # not read 2FA state, not that the account is unprotected.
    if identity.get("mfa_enabled") is not False:
        return True
    return not has_admin_grant(resource)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }
