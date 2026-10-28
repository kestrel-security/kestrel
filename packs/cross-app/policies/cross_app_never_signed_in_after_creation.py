# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-never-signed-in-after-creation"
TITLE = "Account created more than 30 days ago that has never signed in"
SEVERITY = "low"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This enabled account was created over 30 days ago and the application has never recorded "
    "a sign-in or activity for it. It is either provisioned for someone who never arrived, a "
    "duplicate, or a standing account waiting to be misused. Applications that cannot report "
    "activity (GitHub's audit log sees only administrative actions) are not assessable."
)
REMEDIATION = (
    "Confirm whether the person needs the account; remove it if not, and review why "
    "provisioning ran ahead of the start date."
)
COMPLIANCE = {"soc2": ["CC6.2"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-08"]}
REQUIRES = ["identity:last_sign_in"]

HUMAN_IDENTITY_TYPES = ("user",)
GRACE_DAYS = 30


def policy(resource):
    """True = compliant. Evaluated per account."""
    identity = resource.get("identity") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if identity.get("is_disabled"):
        return True
    created = identity.get("created_at_source")
    if created is None or within_last_days(created, GRACE_DAYS):
        return True
    return activity_status(resource, GRACE_DAYS) != "never"


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.created_at_source": identity.get("created_at_source"),
        "days_since_created": days_since(identity.get("created_at_source")),
        "application.name": application.get("name"),
    }
