# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-no-idp-account"
TITLE = "Company account exists in an application but not in the identity provider"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "A person signs in to this application with a company address, yet has no account in any "
    "connected identity provider. Nothing about them is governed by SSO: no central MFA policy, "
    "no session control, and no offboarding step that will ever reach them."
)
REMEDIATION = (
    "Create the identity-provider account and convert the application account to SSO, or remove "
    "the local account if it was never meant to exist. Where the application supports it, disable "
    "non-SSO sign-in so a replacement cannot be created the same way."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.2"], "cis": ["5.2"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-02"]}

HUMAN_IDENTITY_TYPES = ("user",)
# Applications that *are* the identity provider: an account there is the thing
# this policy asks about, so it can never be missing from itself.
IDP_APPLICATION_TYPES = ("okta", "google_workspace")


def policy(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}

    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if application.get("type") in IDP_APPLICATION_TYPES:
        return True
    # Guests, outside collaborators, and partner accounts are expected to have
    # no account in our directory; that is what makes them external.
    if identity.get("is_external"):
        return True
    if identity.get("is_disabled"):
        return True
    # Without an email there is nothing to correlate on, so "no IdP account"
    # would be an artifact of the missing address rather than a finding.
    if not identity.get("email"):
        return True
    # Only meaningful once an identity provider is actually connected.
    if cluster.get("idp_connected") is not True:
        return True
    return cluster.get("idp_status") != "absent"


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
        "cluster.application_types": cluster.get("application_types"),
        "cluster.idp_status": cluster.get("idp_status"),
        "roles": resource.get("roles") or [],
    }
