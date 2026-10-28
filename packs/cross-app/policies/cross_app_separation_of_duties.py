# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-separation-of-duties"
TITLE = "Same person administers the identity provider and a downstream application"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "One person holds a privileged role in the identity provider and in a connected application "
    "it governs. Whoever can change who people are (create accounts, reset factors, assign apps) "
    "should not also be able to change what those people can do downstream: the two together "
    "let a single account provision itself unreviewed access anywhere."
)
REMEDIATION = (
    "Split the roles across two people, or keep one and record a reviewed exception with a "
    "compensating control (break-glass account, admin session review)."
)
COMPLIANCE = {"soc2": ["CC6.3"], "cis": ["5.4"], "nist_csf": ["PR.AC-4"], "custom": ["XAPP-11"]}

HUMAN_IDENTITY_TYPES = ("user",)
# (application type A, application type B): privileged in both is a conflict.
CONFLICTING_PAIRS = (
    ("okta", "github"),
    ("okta", "slack"),
    ("google_workspace", "github"),
    ("google_workspace", "slack"),
)


def conflicts(privileged_types):
    return [pair for pair in CONFLICTING_PAIRS if pair[0] in privileged_types and pair[1] in privileged_types]


def policy(resource):
    """True = compliant. One finding per person, on the representative account."""
    identity = resource.get("identity") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if not is_representative(resource):
        return True
    privileged = {a.get("application_type") for a in cluster_accounts(resource, active_only=True) if has_privileged_role(a)}
    return not conflicts(privileged)


def evidence(resource):
    identity = resource.get("identity") or {}
    accounts = [a for a in cluster_accounts(resource, active_only=True) if has_privileged_role(a)]
    privileged = {a.get("application_type") for a in accounts}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "conflicts": [list(pair) for pair in conflicts(privileged)],
        "privileged_roles": [{"application_type": a.get("application_type"), "roles": a.get("roles")} for a in accounts],
    }
