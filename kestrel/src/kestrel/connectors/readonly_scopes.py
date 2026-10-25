# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Reject known write/admin scopes declared on connector manifests."""

from __future__ import annotations

from kestrel.connectors.sdk.manifest import ConnectorManifest

# Provider-agnostic substrings that indicate write or admin mutation intent.
_WRITE_SCOPE_MARKERS = (
    ".write",
    ".manage",
    "readwrite",
    "read_write",
    ":write",
    ".fullcontrol",
    "full_control",
)

# Explicit denylist for common SaaS write scopes (case-insensitive match).
_DENIED_SCOPES = frozenset(
    {
        "repo",  # GitHub classic write to private repos — prefer read-only metadata
        "admin:org",
        "admin:repo_hook",
        "delete_repo",
        "okta.users.manage",
        "okta.groups.manage",
        "okta.apps.manage",
        "okta.roles.manage",
        "directory.readwrite.all",
        "user.readwrite.all",
        "group.readwrite.all",
        "application.readwrite.all",
        "sites.fullcontrol.all",
        "mail.readwrite",
        "files.readwrite.all",
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.group",
        "chat:write",
        "admin",
    }
)

# First-party exceptions for scopes that the provider only ships in a
# write-shaped form but that Kestrel uses read-only. Documented in each
# connector's setup guide; prefer a true readonly credential when one exists.
_ALLOWLIST_BY_CONNECTOR: dict[str, frozenset[str]] = {
    # Classic `repo` is required for private-repo collaborator inventory;
    # GitHub App metadata read is the preferred alternative.
    "github": frozenset({"repo"}),
    # Alert Center has no `*.readonly` scope; Kestrel only lists alerts.
    "google_workspace": frozenset({"https://www.googleapis.com/auth/apps.alerts"}),
}


class ReadOnlyScopeError(ValueError):
    """Manifest declares a scope that is not read-only."""


def assert_read_only_scopes(manifest: ConnectorManifest) -> None:
    """Raise ReadOnlyScopeError if required_scopes includes known write scopes."""
    allow = {s.casefold() for s in _ALLOWLIST_BY_CONNECTOR.get(manifest.name, frozenset())}
    offenders: list[str] = []
    for scope in manifest.required_scopes:
        key = scope.strip().casefold()
        if not key or key in allow:
            continue
        if key in _DENIED_SCOPES or any(marker in key for marker in _WRITE_SCOPE_MARKERS):
            # Avoid flagging *.readonly / *.read.All
            if key.endswith(".readonly") or key.endswith(".read.only") or key.endswith(".read.all"):
                continue
            if "readonly" in key or key.endswith(":read") or key.endswith(".read"):
                continue
            offenders.append(scope)
    if offenders:
        raise ReadOnlyScopeError(
            f"Connector '{manifest.name}' declares non-read-only scopes: {offenders}. "
            "Kestrel's connector framework is read-only by design."
        )
