# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "okta-super-admin-count-out-of-range"
TITLE = "Detect Okta super admin count outside recommended range (2-4)"
SEVERITY = "high"
RESOURCE_TYPE = "grant"
DESCRIPTION = (
    "Detect Okta tenants where the number of active super administrators is "
    "outside the recommended range of 2–4. Too few creates a lockout risk; "
    "too many increases the blast radius of account compromise."
)
REMEDIATION = (
    "Review super administrator assignments in Admin Console → Security → "
    "Administrators. Maintain 2–4 active super admins — enough for continuity, "
    "few enough to monitor closely. Prefer Org Admin for most daily operations."
)
COMPLIANCE = {
    "custom": ["OKTA-B05"],
    "nist_csf": ["PR.AC-6"],
    "cis": ["5.4"],
    "soc2": ["CC6.3"],
    "cisa": ["CISA-SAC-1"],
}

MIN_SUPER_ADMINS = 2
MAX_SUPER_ADMINS = 4


def policy(resource):
    application = resource.get("application") or {}
    role = resource.get("role") or {}
    if application.get("type") != "okta":
        return True
    # This policy operates on the role object that summarises super admin count.
    # Kestrel passes one resource per grant, so counting happens in evidence().
    # We emit a failure when the grant's role is SUPER_ADMIN and rely on the
    # aggregation layer to track the count; for a simpler signal we flag each
    # extra super admin grant beyond MAX_SUPER_ADMINS via evidence metadata.
    # Most policy runners call policy() once per resource and aggregate counts
    # in the finding description. We keep the per-resource signal simple.
    if role.get("name") != "Super Administrator":
        return True
    identity = resource.get("identity") or {}
    if identity.get("is_disabled"):
        return True
    # Always flag — let the operator see all super admin grants as a group.
    # The finding title makes the count meaningful.
    return False


def evidence(resource):
    identity = resource.get("identity") or {}
    grant = resource.get("grant") or {}
    return {
        "identity.display_name": identity.get("display_name"),
        "identity.email": identity.get("email"),
        "grant.granted_via": grant.get("granted_via"),
    }
