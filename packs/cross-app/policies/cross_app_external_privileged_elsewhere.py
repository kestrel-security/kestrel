# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-external-privileged-elsewhere"
TITLE = "Person treated as a guest in one application holds a privileged role in another"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "The same person is a guest, outside collaborator, or partner account in one connected "
    "application, and an administrator in another. Each console shows half of that: the one that "
    "marked them external has no idea they are an admin somewhere else, and the one that granted "
    "the admin role has no idea the company considers them an outsider."
)
REMEDIATION = (
    "Decide which of the two is wrong. If the person is staff, correct the account that marks "
    "them external so guest-scoped controls stop applying to them; if they are genuinely a "
    "contractor or partner, remove the privileged role and grant the narrowest access that lets "
    "them do the work."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"], "custom": ["XAPP-04"]}

HUMAN_IDENTITY_TYPES = ("user",)


def policy(resource):
    """True = compliant.

    Evaluated once per account and reported against the *privileged* one --
    the role an operator would remove -- not against the guest account, which
    is usually the correct half.

    Distinct from the per-application guest-with-admin checks
    (`slack-external-privileged` and friends): those need both facts inside one
    application, where an admin can already see them. This one needs two
    applications and the correlation between them, so no single console can
    raise it.
    """
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}

    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if identity.get("is_disabled"):
        return True
    # Report against the privileged account; the guest account stays quiet.
    if identity.get("is_external"):
        return True
    app_type = application.get("type")
    accounts = cluster_accounts(resource)
    if not any(has_privileged_role(account) and account.get("application_type") == app_type for account in accounts):
        return True
    # An account the *same* application already marks external is that
    # application's own problem, and its own policy reports it. A disabled
    # guest account elsewhere no longer marks the person as an outsider.
    return not any(
        account.get("is_external") and not account.get("is_disabled") and account.get("application_type") != app_type
        for account in accounts
    )


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    cluster = resource.get("cluster") or {}
    accounts = cluster.get("accounts") or []
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "application.name": application.get("name"),
        "roles": resource.get("roles") or [],
        "external_in": sorted(
            {
                account.get("application_name") or account.get("application_type")
                for account in accounts
                if account.get("is_external") and not account.get("is_disabled")
            }
        ),
        "cluster.match_kind": cluster.get("match_kind"),
        "cluster.application_types": cluster.get("application_types"),
    }
