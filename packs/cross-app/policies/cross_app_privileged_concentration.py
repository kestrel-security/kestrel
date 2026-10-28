# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-privileged-concentration"
TITLE = "Privileged roles concentrated across multiple SaaS applications for the same person"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Privileged roles concentrated across multiple SaaS applications for the same person"
REMEDIATION = (
    "Review whether the same person needs privileged roles in multiple applications; remove unnecessary admin assignments."
)
COMPLIANCE = {"soc2": ["CC6.3"], "cis": ["5.2"], "nist_csf": ["PR.AC-4"], "custom": ["GH-01"]}


def policy(resource):
    """True = compliant.

    Rows carry ``cluster.privileged_application_types`` — the applications
    where the *correlated person* holds a privileged role, which is stronger
    than the older email-only key because it also collapses accounts matched
    by a unique display name. The legacy top-level
    ``privileged_application_types`` remains the fallback for fixtures and for
    rows loaded before correlation was materialized.

    Only the representative account opens the finding, so one person who is an
    admin in four applications is one finding, not four.
    """
    if not has_privileged_role(resource):
        return True
    cluster = resource.get("cluster") or {}
    apps = cluster.get("privileged_application_types")
    if not isinstance(apps, list):
        apps = resource.get("privileged_application_types")
    if not isinstance(apps, list):
        return True
    distinct = list({str(app) for app in apps if app})
    if len(distinct) < 2:
        return True
    # One finding per person: the cluster names a representative, and every
    # other account defers to it. Rows without a representative (no
    # correlation yet) each stand for themselves.
    if not is_representative(resource):
        return True
    return False


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "application.type": application.get("type"),
        "roles": resource.get("roles") or [],
        "privileged_application_types": (resource.get("cluster") or {}).get("privileged_application_types")
        or resource.get("privileged_application_types")
        or [],
        "cluster.accounts": [
            {
                "application_type": account.get("application_type"),
                "roles": account.get("roles"),
                "privileged": account.get("privileged"),
            }
            for account in ((resource.get("cluster") or {}).get("accounts") or [])
        ],
    }
