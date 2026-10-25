# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-departed-still-has-access"
TITLE = "Account disabled in the identity provider is still active in another application"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This person's identity-provider account has been disabled -- the offboarding step every "
    "process gets right -- but they still hold an enabled account in another connected "
    "application. Single sign-on does not reach a local account, so the access survives the "
    "deprovisioning that was supposed to end it."
)
REMEDIATION = (
    "Disable or delete the remaining account in the application named in the evidence, then "
    "confirm the offboarding checklist covers applications that keep local accounts alongside SSO."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-01"]}

# Non-human accounts outlive people by design: a bot or API token has no
# joiner-mover-leaver lifecycle, and flagging them here would bury the finding
# that matters.
HUMAN_IDENTITY_TYPES = ("user",)


def policy(resource):
    """True = compliant.

    Evaluated once per account. Only the surviving (enabled, non-IdP) account
    opens a finding, so one departed person with two live accounts is two
    findings against the two accounts an operator has to go and disable --
    not one finding they have to read twice.
    """
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}

    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    # The IdP account itself being disabled is the correct end state.
    if application.get("type") in (cluster.get("idp_application_types") or []):
        return True
    if identity.get("is_disabled"):
        return True
    return cluster.get("idp_status") != "disabled"


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    disabled_in = [
        account.get("application_name") or account.get("application_type")
        for account in (cluster.get("accounts") or [])
        if account.get("is_disabled")
    ]
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "application.name": application.get("name"),
        "cluster.idp_status": cluster.get("idp_status"),
        "cluster.disabled_in": disabled_in,
        "cluster.application_types": cluster.get("application_types"),
        "cluster.roles_here": resource.get("roles") or [],
    }
