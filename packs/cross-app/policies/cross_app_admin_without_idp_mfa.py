# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-admin-without-idp-mfa"
TITLE = "Administrator in a connected application whose identity-provider account has no MFA"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This person holds a privileged role in at least one connected application, and the "
    "identity-provider account they sign in through does not have multi-factor authentication. "
    "A per-application MFA check cannot see this: the application trusts the single sign-on "
    "assertion, and the identity provider does not know what the person administers downstream."
)
REMEDIATION = (
    "Enroll the identity-provider account in MFA (and require it for administrators by policy), "
    "or remove the privileged roles named in the evidence until it is."
)
COMPLIANCE = {"soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"], "custom": ["XAPP-07"]}

HUMAN_IDENTITY_TYPES = ("user",)


def policy(resource):
    """True = compliant. One finding per person, on the representative account."""
    identity = resource.get("identity") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    # A deploy bot provisioned as a regular user is still not a person.
    if worker_type_of(resource) == "service":
        return True
    if not is_representative(resource):
        return True
    idp = idp_account(resource)
    if idp is None or idp.get("is_disabled"):
        return True
    # Only an explicit False is a finding: None means the provider could not read it.
    if idp.get("mfa_enabled") is not False:
        return True
    privileged = [a for a in cluster_accounts(resource, active_only=True) if has_privileged_role(a)]
    return not privileged


def evidence(resource):
    identity = resource.get("identity") or {}
    idp = idp_account(resource) or {}
    privileged = [a for a in cluster_accounts(resource, active_only=True) if has_privileged_role(a)]
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "idp.application_type": idp.get("application_type"),
        "idp.mfa_enabled": idp.get("mfa_enabled"),
        "privileged_in": sorted({a.get("application_name") or a.get("application_type") for a in privileged}),
        "privileged_roles": [{"application_type": a.get("application_type"), "roles": a.get("roles")} for a in privileged],
    }
