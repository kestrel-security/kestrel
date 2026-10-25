# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-oauth-grant-outlives-account"
TITLE = "OAuth authorization still active for an account that has been deprovisioned"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This person has been disabled -- in the identity provider, in this application, or both -- "
    "and the OAuth applications they authorized still hold live grants. A token issued by consent "
    "does not go through the sign-in path, so disabling the account does not revoke it: the "
    "third-party application keeps reading the data it was granted, under a person who no longer "
    "works here."
)
REMEDIATION = (
    "Revoke the grants named in the evidence from the application's OAuth or connected-apps "
    "console, then add token revocation to the offboarding checklist -- disabling the account is "
    "not enough on its own."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-03"]}

HUMAN_IDENTITY_TYPES = ("user",)


def policy(resource):
    """True = compliant.

    The companion to `cross-app-departed-still-has-access`, and deliberately
    its mirror image: that policy fires on accounts still *enabled* after the
    identity provider disabled the person, and skips the disabled ones as the
    correct end state. This one fires precisely because the account is
    disabled. Correct end state for the account, not for its tokens.
    """
    identity = resource.get("identity") or {}
    cluster = resource.get("cluster") or {}
    grants = resource.get("oauth_grants") or []

    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if not grants:
        return True
    return not (identity.get("is_disabled") or cluster.get("idp_status") == "disabled")


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    grants = resource.get("oauth_grants") or []
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_disabled": identity.get("is_disabled"),
        "application.name": application.get("name"),
        "cluster.idp_status": cluster.get("idp_status"),
        "cluster.application_types": cluster.get("application_types"),
        "oauth_grant_count": len(grants),
        "oauth_grants": [
            {
                "name": grant.get("oauth_application_name"),
                "publisher": grant.get("publisher"),
                "is_verified": grant.get("is_verified"),
                "sensitive_scope_names": grant.get("sensitive_scope_names"),
                "last_used_at": grant.get("last_used_at"),
            }
            for grant in grants
        ],
    }
