# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "cross-app-group-scoped-privilege"
TITLE = "Member of a contractor or guest group who holds a privileged role in another application"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "This account is in a group the organization uses to mark contingent or guest access "
    "(contractors, vendors, guests), and the same person is an administrator in another "
    "connected application. The group is how the directory says 'limited access'; the admin "
    "role elsewhere says the opposite, and neither console sees both."
)
REMEDIATION = (
    "Remove the privileged role named in the evidence, or move the person out of the "
    "contingent group if the directory is wrong about them."
)
COMPLIANCE = {"soc2": ["CC6.1", "CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-4"], "custom": ["XAPP-04"]}
REQUIRES = ["identity:groups"]

HUMAN_IDENTITY_TYPES = ("user",)
GROUP_PATTERNS = ("contractor*", "*contractors*", "vendor*", "*vendors*", "guest*", "*guests*", "*/contractors*")


def policy(resource):
    """True = compliant. Reported on the group member's account, naming the
    other applications where the person is privileged."""
    identity = resource.get("identity") or {}
    if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:
        return True
    if identity.get("is_disabled"):
        return True
    if not in_group(resource, GROUP_PATTERNS):
        return True
    elsewhere = cluster_accounts(resource, include_self=False, active_only=True)
    return not any(has_privileged_role(a) for a in elsewhere)


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    privileged = [a for a in cluster_accounts(resource, include_self=False, active_only=True) if has_privileged_role(a)]
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "application.name": application.get("name"),
        "groups": [name for name in resource.get("groups") or [] if matches_any(name, GROUP_PATTERNS)],
        "privileged_in": sorted({a.get("application_name") or a.get("application_type") for a in privileged}),
    }
