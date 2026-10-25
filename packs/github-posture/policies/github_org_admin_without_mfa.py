# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "github-org-admin-without-mfa"
TITLE = "GitHub organization administrators without MFA enabled"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Flags GitHub organization administrators without MFA enabled"
REMEDIATION = "Require MFA for the account or remove the organization administrator role."
COMPLIANCE = {"custom": ["GH-01"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    roles = resource.get("roles") or []
    if application.get("type") != "github":
        return True
    if "organization_admin" not in roles:
        return True
    # Tri-state. `mfa_enabled` is None when the credential could not read the
    # org's 2FA state (that filter needs org ownership). Treating unknown as
    # "no MFA" would open a finding on every administrator the moment a token
    # loses one permission, so only an explicit False is a violation. The
    # unreadable state is surfaced by connector health and the run's reduced
    # coverage note instead.
    return identity.get("mfa_enabled") is not False


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "identity.is_external": identity.get("is_external"),
        "identity.roles": resource.get("roles"),
        "application.name": application.get("name"),
        "application.display_name": application.get("display_name"),
        "application.external_tenant_ref": application.get("external_tenant_ref"),
    }
