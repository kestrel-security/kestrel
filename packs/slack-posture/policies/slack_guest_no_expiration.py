# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "slack-guest-no-expiration"
TITLE = "Detect Slack guest accounts without an expiration date"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = (
    "Guest accounts without an expiration date remain active indefinitely. "
    "Contractors, partners, and other external collaborators should have an "
    "expiry set so access is automatically revoked when engagement ends."
)
REMEDIATION = (
    "In Slack Admin → Members → select the guest → Set expiration date. "
    "Set the expiration to the end of the engagement or contract period."
)
COMPLIANCE = {"nist_csf": ["PR.AC-1"], "soc2": ["CC6.2"], "cis": ["6.3"]}


def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "slack":
        return True
    if identity.get("is_disabled"):
        return True
    guest_type = identity.get("guest_type")
    if not guest_type:
        return True
    # expires_at is populated from expiration_ts when Slack includes it.
    return identity.get("expires_at") is not None


def evidence(resource):
    identity = resource.get("identity") or {}
    application = resource.get("application") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.guest_type": identity.get("guest_type"),
        "identity.expires_at": identity.get("expires_at"),
        "application.name": application.get("name"),
    }
