# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-contractor-dormant-in-app"
TITLE = "Contractor account enabled in an application they have not signed into for 30 days"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This person is a contractor or vendor according to the identity provider or an operator "
    "classification rule, this account is enabled, and the application has seen no sign-in or "
    "activity from it in 30 days. Contingent access that is not being used is access that "
    "should have ended with the engagement. An account whose provider cannot report activity "
    "(a profile-modified time, or GitHub's audit log alone) is not assessable and passes; a "
    "person whose worker type is unknown is not shown to be a contractor and passes."
)
REMEDIATION = (
    "Confirm the engagement is still active; if not, disable the account in the application named "
    "in the evidence. If the person is staff, correct their worker type in the identity provider or "
    "the classification rules."
)
COMPLIANCE = {"soc2": ["CC6.2", "CC6.3"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-05"]}
REQUIRES = ["identity:worker_type", "identity:last_sign_in"]

HUMAN_IDENTITY_TYPES = ("user",)
CONTINGENT_WORKER_TYPES = ("contractor", "vendor_or_partner")
STALE_DAYS = 30


def policy(resource):
    """True = compliant. Evaluated once per account, including the identity
    provider's own, so each unused account is its own finding."""
    identity = resource.get("identity") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if identity.get("is_disabled"):
        return True
    if worker_type_of(resource) not in CONTINGENT_WORKER_TYPES:
        return True
    status = activity_status(resource, STALE_DAYS)
    if status == "unknown":
        return True
    return status == "active"


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "identity.last_active_source": identity.get("last_active_source"),
        "application.name": application.get("name"),
        "worker_type": worker_type_of(resource),
        "cluster.worker_type_source": cluster.get("worker_type_source"),
        "cluster.last_active_at": cluster.get("last_active_at"),
        "activity_status": activity_status(resource, STALE_DAYS),
    }
