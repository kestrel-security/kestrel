# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared normalized activity-event action vocabulary.

Connectors map vendor audit / report event names onto these keys. The
Changes actor overlay (`kestrel.changes.overlay`) and event-detection
policies key off the same strings, so widening a connector's curated
taxonomy widens attribution and detections without a feed change.

Audit-derived setting changes (Slack ``pref_*``, GWS
``CHANGE_APPLICATION_SETTING``) map to ``config.change`` / ``policy.change``
/ ``sso.change`` and reach operators only as Findings — never as current
state settings and never as Changes rows (DEC-024).
"""

from __future__ import annotations

# Canonical actions every first-party connector may emit. Connectors may
# use a subset; unknown actions are dropped at normalize time.
NORMALIZED_ACTIONS: frozenset[str] = frozenset(
    {
        # Privilege and access
        "privilege.grant",
        "privilege.revoke",
        "privilege.external",
        "access.grant",
        "access.revoke",
        "group.member.add",
        "group.member.remove",
        "service_account.escalate",
        # Identity lifecycle
        "identity.add",
        "identity.deactivate",
        "identity.guest",
        "dormant.reactivate",
        # Auth / MFA / credentials
        "auth.failure",
        "auth.success",
        "mfa.disable",
        "mfa.enable",
        "credential.change",
        "session.reset",
        "sso.change",
        # OAuth / apps
        "oauth.app.install",
        "oauth.app.revoke",
        "oauth.scope.expand",
        "oauth.sensitive_consent",
        "token.grant",
        "api.token.create",
        # Sharing / external
        "sharing.external",
        # Configuration / policy
        "config.change",
        "policy.change",
        "branch_protection.disable",
        "webhook.create",
        "deploy_key.create",
        # Threat / support / admin
        "threat.detected",
        "admin.console",
        "support.access",
        "data.export",
        # Devices
        "device.enroll",
        "device.wipe",
        "device.compromise",
        "device.compliance_fail",
    }
)

# Category for each action. Used when emitting ActivityEvent rows.
ACTION_CATEGORIES: dict[str, str] = {
    "privilege.grant": "privilege",
    "privilege.revoke": "privilege",
    "privilege.external": "privilege",
    "access.grant": "access",
    "access.revoke": "access",
    "group.member.add": "group",
    "group.member.remove": "group",
    "service_account.escalate": "privilege",
    "identity.add": "identity",
    "identity.deactivate": "identity",
    "identity.guest": "identity",
    "dormant.reactivate": "identity",
    "auth.failure": "auth",
    "auth.success": "auth",
    "mfa.disable": "mfa",
    "mfa.enable": "mfa",
    "credential.change": "credential",
    "session.reset": "session",
    "sso.change": "sso",
    "oauth.app.install": "oauth",
    "oauth.app.revoke": "oauth",
    "oauth.scope.expand": "oauth",
    "oauth.sensitive_consent": "oauth",
    "token.grant": "oauth",
    "api.token.create": "credential",
    "sharing.external": "sharing",
    "config.change": "config",
    "policy.change": "policy",
    "branch_protection.disable": "config",
    "webhook.create": "config",
    "deploy_key.create": "config",
    "threat.detected": "threat",
    "admin.console": "admin",
    "support.access": "support",
    "data.export": "data",
    "device.enroll": "device",
    "device.wipe": "device",
    "device.compromise": "device",
    "device.compliance_fail": "device",
}


def category_for(action: str) -> str:
    """Return the action_category for a normalized action, or ``other``."""
    return ACTION_CATEGORIES.get(action, "other")
