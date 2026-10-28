# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Constants the row loader, the sync, and the policy sandbox all read.

Dependency-free on purpose: ``dataload`` imports this, the runtime package
imports ``dataload``, and the helpers module re-exports these names into every
policy, so the vocabulary cannot live in any of them without a cycle.
"""

from __future__ import annotations

#: ``last_active_source`` values that record something the account actually
#: did: the provider's own last sign-in field (``login``), an audit-log entry
#: the account produced (``audit``), or a provider usage report
#: (``analytics``). ``profile`` is a profile-modification time and says nothing
#: about activity; dormancy checks must not read it.
TRUSTED_ACTIVITY_SOURCES: frozenset[str] = frozenset({"login", "audit", "analytics"})

#: Application types that are an identity provider: the account there is the
#: one an offboarding process disables first, so its state is what "this
#: person has left" means.
IDP_APPLICATION_TYPES: frozenset[str] = frozenset({"okta", "google_workspace"})

#: Substrings that mark a role name as privileged, across every connector.
PRIVILEGED_ROLE_HINTS: tuple[str, ...] = (
    "admin",
    "owner",
    "super_admin",
    "organization_admin",
    "help_desk_admin",
    "groups_admin",
)

#: Application types whose only activity signal is a lower bound: GitHub's
#: org audit log records administrative actions, not sign-ins or pushes, so
#: an account with no observation there may be in daily use. ``activity_status``
#: reports such accounts as ``unknown`` rather than ``never``.
PARTIAL_ACTIVITY_APPLICATION_TYPES: frozenset[str] = frozenset({"github"})
