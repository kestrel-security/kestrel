# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-departed-account-outlived-offboarding"
TITLE = "Account still enabled more than a week after the identity provider disabled the person"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "The identity provider disabled this person's account more than 7 days ago and this "
    "application still has an enabled account for them. The companion policy reports the "
    "survivor the moment the identity provider acts; this one measures how long offboarding "
    "has been incomplete, so a process that is merely slow and one that never reaches local "
    "accounts can be told apart."
)
REMEDIATION = (
    "Disable or delete the account in the application named in the evidence, then fix the "
    "offboarding runbook so applications that keep local accounts are covered within the grace period."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-06"]}
REQUIRES = ["identity:disabled_at"]

HUMAN_IDENTITY_TYPES = ("user",)
GRACE_DAYS = 7


def policy(resource):
    """True = compliant. Reported on the surviving account, never the
    identity-provider account that is already disabled."""
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    # A deploy bot provisioned as a regular user is still not a person.
    if worker_type_of(resource) == "service":
        return True
    if identity.get("is_disabled"):
        return True
    if application.get("type") in (cluster.get("idp_application_types") or []):
        return True
    idp = idp_account(resource)
    if idp is None or not idp.get("is_disabled"):
        return True
    disabled_at = idp.get("disabled_at")
    if disabled_at is None:
        # The provider did not say when; the companion policy already reports it.
        return True
    return within_last_days(disabled_at, GRACE_DAYS)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    idp = idp_account(resource) or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "application.name": application.get("name"),
        "idp.application_type": idp.get("application_type"),
        "idp.disabled_at": idp.get("disabled_at"),
        "days_since_idp_disabled": days_since(idp.get("disabled_at")),
    }
