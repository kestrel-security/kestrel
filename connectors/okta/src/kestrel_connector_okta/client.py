# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Thin typed wrapper over Transport for Okta Management API v1.

Every method builds a `path` (including query string) that FixtureTransport
matches on. List endpoints walk RFC 5988 `Link` pagination on live transports
and return the full fixture list in one page under FixtureTransport.

List results are cached on the client for the lifetime of one collector so a
sync does not re-walk users/groups/apps for memberships, roles, and assignments.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from kestrel.connectors.sdk.base import Transport

# Okta Management API max page size for most list endpoints.
PAGE_LIMIT = 200
# System Log allows up to 1000; stay at 200 so Link walks stay consistent.
LOG_PAGE_LIMIT = 200


class OktaClient:
    def __init__(self, transport: Transport, org_url: str) -> None:
        self.transport = transport
        self.org_url = org_url.rstrip("/")
        self._list_cache: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def _as_item_dicts(item: Any) -> list[dict[str, Any]]:
        """Normalize one paginate() yield to resource dict rows.

        Fixture/live list pages yield one resource dict per item. A rare
        non-list envelope (no resource ``id``) may wrap a named array.
        """
        if not isinstance(item, dict):
            return []
        if "id" in item or "uuid" in item:
            return [item]
        for key in ("users", "groups", "apps", "roles", "factors", "value"):
            nested = item.get(key)
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
        return [item]

    def _list(self, path: str) -> list[dict[str, Any]]:
        cached = self._list_cache.get(path)
        if cached is not None:
            return cached
        items: list[dict[str, Any]] = []
        for page_item in self.transport.paginate("GET", path):
            items.extend(self._as_item_dicts(page_item))
        self._list_cache[path] = items
        return items

    def get_org(self) -> dict[str, Any]:
        # Live Org Settings API is GET /api/v1/org (not /orgs/default).
        return self.transport.request("GET", "/api/v1/org")

    def probe_users(self) -> Any:
        """Single-page health probe (does not walk Link pagination)."""
        return self.transport.request("GET", "/api/v1/users?limit=1")

    def probe_groups(self) -> Any:
        return self.transport.request("GET", "/api/v1/groups?limit=1")

    def probe_apps(self) -> Any:
        return self.transport.request("GET", "/api/v1/apps?limit=1")

    def probe_user_roles(self, user_id: str) -> Any:
        """Single-page probe that the token can read classic admin roles."""
        return self.transport.request("GET", f"/api/v1/users/{quote(user_id)}/roles?limit=1")

    def probe_logs(self) -> Any:
        """Single-page System Log probe (does not walk Link pagination)."""
        return self.transport.request("GET", "/api/v1/logs?limit=1")

    def list_users(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/users?limit={PAGE_LIMIT}")

    def list_user_factors(self, user_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/users/{quote(user_id)}/factors?limit={PAGE_LIMIT}")

    def list_role_assignees(self) -> list[dict[str, Any]]:
        """Users that hold at least one admin role (``/iam/assignees/users``).

        Turns the role walk from one call per directory user into one call per
        admin. Older orgs answer 404; the collector falls back to the full walk.
        """
        return self._list(f"/api/v1/iam/assignees/users?limit={PAGE_LIMIT}")

    def list_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/users/{quote(user_id)}/roles?limit={PAGE_LIMIT}")

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/groups?limit={PAGE_LIMIT}")

    def list_group_users(self, group_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/groups/{quote(group_id)}/users?limit={PAGE_LIMIT}")

    def list_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Classic admin roles assigned to a group (not IAM custom roles)."""
        return self._list(f"/api/v1/groups/{quote(group_id)}/roles?limit={PAGE_LIMIT}")

    def list_apps(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/apps?limit={PAGE_LIMIT}")

    def list_app_users(self, app_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/apps/{quote(app_id)}/users?limit={PAGE_LIMIT}")

    def list_app_grants(self, app_id: str) -> list[dict[str, Any]]:
        """Okta API scopes actually granted to an OAuth service integration
        (``/apps/{id}/grants``), as opposed to the scopes it merely lists."""
        return self._list(f"/api/v1/apps/{quote(app_id)}/grants?limit={PAGE_LIMIT}")

    def list_app_groups(self, app_id: str) -> list[dict[str, Any]]:
        """Groups assigned to an application (members inherit the app)."""
        return self._list(f"/api/v1/apps/{quote(app_id)}/groups?limit={PAGE_LIMIT}")

    def list_system_logs(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        """Walk System Log Link pages. Okta defaults to the last 7 days when
        ``since`` is omitted. Pass ``since`` for incremental syncs."""
        path = f"/api/v1/logs?limit={LOG_PAGE_LIMIT}&sortOrder=DESCENDING"
        if since is not None:
            stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            path = f"{path}&since={stamp}"
        return self._list(path)

    def list_policies(self, policy_type: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/policies?type={quote(policy_type)}&limit={PAGE_LIMIT}")

    def get_threat_insight_configuration(self) -> dict[str, Any]:
        return self.transport.request("GET", "/api/v1/threats/configuration")

    def list_api_tokens(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/api-tokens?limit={PAGE_LIMIT}")

    # -- authentication and session policy surface ----------------
    #
    # Okta policies are containers; the controls live in their *rules*. A
    # sign-on policy says nothing on its own -- whether a session lasts eight
    # hours or thirty days, whether a network zone is required, and which
    # authenticators satisfy it are all rule properties. Reading policies
    # without rules, which is what Kestrel did reads the
    # folder and not the file.

    def list_policy_rules(self, policy_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/policies/{quote(policy_id)}/rules?limit={PAGE_LIMIT}")

    def list_authenticators(self) -> list[dict[str, Any]]:
        """Enrolled authenticator types and their status.

        Which of these is active decides whether an org can be phished: an
        `okta_verify` push and a WebAuthn key are not equivalent controls.
        """
        return self._list("/api/v1/authenticators")

    def list_device_assurance_policies(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/device-assurances")

    # -- perimeter and automation surface -------------------------
    #
    # Everything here decides who can reach the org and what runs when they
    # do. Hooks are the sharpest: an inline hook executes *during*
    # authentication and can change its outcome, so whoever controls that
    # endpoint controls the sign-in.

    def list_network_zones(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/zones?limit={PAGE_LIMIT}")

    def list_trusted_origins(self) -> list[dict[str, Any]]:
        """Origins allowed to make cross-origin calls and receive redirects.

        A trusted origin an attacker controls can receive a token, so this is
        an authentication boundary, not a CORS convenience setting.
        """
        return self._list(f"/api/v1/trustedOrigins?limit={PAGE_LIMIT}")

    def list_event_hooks(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/eventHooks")

    def list_inline_hooks(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/inlineHooks")

    def list_identity_providers(self) -> list[dict[str, Any]]:
        """Inbound federation. An IdP that can assert any user is a full
        authentication bypass for whoever operates it."""
        return self._list(f"/api/v1/idps?limit={PAGE_LIMIT}")

    def list_group_rules(self) -> list[dict[str, Any]]:
        """Dynamic group membership. A rule targeting a privileged group turns
        a profile attribute into a privilege grant."""
        return self._list(f"/api/v1/groups/rules?limit={PAGE_LIMIT}")

    # -- IAM / privilege model ------------------------------------
    #
    # Custom IAM roles differ from the classic admin catalog: they are
    # composable, resource-scoped, and may be org-wide or constrained to a
    # resource set. An org-wide custom role is semantically equivalent to the
    # classic ORG_ADMIN, but invisible to the classic role walk.

    def list_iam_roles(self) -> list[dict[str, Any]]:
        """Custom IAM roles, including their permission list."""
        return self._list(f"/api/v1/iam/roles?limit={PAGE_LIMIT}")

    def list_iam_role_permissions(self, role_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/iam/roles/{quote(role_id)}/permissions?limit={PAGE_LIMIT}")

    def list_resource_sets(self) -> list[dict[str, Any]]:
        """Resource sets scope a custom role to a subset of the directory."""
        return self._list(f"/api/v1/iam/resource-sets?limit={PAGE_LIMIT}")

    # -- Behaviors ------------------------------------------------
    #
    # Behavior detection signals feed adaptive authentication. When
    # evaluateOnSignIn is false for anomalousLocation / anomalousDevice /
    # anomalousIP the org is blind to those signals even if ThreatInsight is on.

    def list_behaviors(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/behaviors?limit={PAGE_LIMIT}")

    # -- Authorization servers ------------------------------------
    #
    # Custom authorization servers have their own access-token policies with
    # potentially long lifetimes and wildcard scopes; they are the "inner"
    # OAuth layer that most posture tools miss.

    def list_authorization_servers(self) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/authorizationServers?limit={PAGE_LIMIT}")

    def list_auth_server_policies(self, server_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/authorizationServers/{quote(server_id)}/policies?limit={PAGE_LIMIT}")

    def list_auth_server_scopes(self, server_id: str) -> list[dict[str, Any]]:
        return self._list(f"/api/v1/authorizationServers/{quote(server_id)}/scopes?limit={PAGE_LIMIT}")

    # -- Log streams ----------------------------------------------

    def list_log_streams(self) -> list[dict[str, Any]]:
        """External SIEM / SYSLOG forwarding destinations. An org with no
        active log stream is shipping events nowhere but Okta's own log."""
        return self._list(f"/api/v1/logStreams?limit={PAGE_LIMIT}")

    # -- Devices --------------------------------------------------

    def list_devices(self) -> list[dict[str, Any]]:
        """Enrolled Okta-managed devices (Okta Device Trust / FastPass)."""
        return self._list(f"/api/v1/devices?limit={PAGE_LIMIT}")

    def list_device_users(self, device_id: str) -> list[dict[str, Any]]:
        """Users linked to a managed device."""
        return self._list(f"/api/v1/devices/{quote(device_id)}/users?limit={PAGE_LIMIT}")

    # -- Additional policy types ----------------------------------

    # -- App features (provisioning) ------------------------------
