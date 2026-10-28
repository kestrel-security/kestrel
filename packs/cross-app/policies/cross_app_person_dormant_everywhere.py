# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-person-dormant-everywhere"
TITLE = "Person with enabled accounts who has not been active in any application for 90 days"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "Every enabled account this person holds across the connected applications is dormant: "
    "the most recent trusted activity on any of them is older than 90 days. A dormant account "
    "in one application can be a tool the person does not use; dormant everywhere is a person "
    "who has probably left without being offboarded, or an account set that was never theirs. "
    "An application that cannot report activity makes the person not assessable."
)
REMEDIATION = (
    "Confirm with the manager whether the person is still with the organization; if not, run "
    "offboarding. If they are, this is a standing account set nobody uses: disable it."
)
COMPLIANCE = {"soc2": ["CC6.2"], "cis": ["5.3"], "nist_csf": ["PR.AC-1"], "custom": ["XAPP-08"]}
REQUIRES = ["identity:last_sign_in"]

HUMAN_IDENTITY_TYPES = ("user",)
DORMANT_DAYS = 90


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
    accounts = cluster_accounts(resource, active_only=True)
    if not accounts:
        return True
    statuses = [activity_status(a, DORMANT_DAYS) for a in accounts]
    if "active" in statuses or "unknown" in statuses:
        return True
    return False


def evidence(resource):
    identity = resource.get("identity") or {}
    cluster = resource.get("cluster") or {}
    accounts = cluster_accounts(resource, active_only=True)
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "cluster.last_active_at": cluster.get("last_active_at"),
        "cluster.application_types": cluster.get("application_types"),
        "accounts": [
            {
                "application_type": a.get("application_type"),
                "last_active_at": a.get("last_active_at"),
                "status": activity_status(a, DORMANT_DAYS),
            }
            for a in accounts
        ],
    }
