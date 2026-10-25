# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Thin typed wrapper over a Transport, translating Google Admin SDK,
Drive, Cloud Identity, and Alert Center API endpoints into method calls.

Like the GitHub client, every method builds a `path` (including query
string) that doubles as the request signature FixtureTransport matches on.

Google's APIs differ from GitHub's in two ways that matter here: results are
wrapped in an envelope (`{"users": [...], "nextPageToken": ...}`) rather than
returned as a bare array, and pagination is token-based rather than
Link-header based. `_list` walks `nextPageToken` on live envelopes; fixtures
store the already-unwrapped list (complete result set, one page).

Cloud Identity and Alert Center APIs use different base hostnames than the
Admin SDK. httpx supports absolute URLs in `client.request()` even when a
base_url is set, so those paths are full URLs beginning with https://. The
FixtureTransport matches on the full string `"GET https://..."` as normal.

directory and Drive lists use customer-wide / domain-admin query
params and raise if a page cap is hit with a remaining token (no silent
truncation).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from kestrel.connectors.sdk.base import Transport

from kestrel_connector_google_workspace.http import PaginationLimitError

DIRECTORY = "/admin/directory/v1"
DRIVE = "/drive/v3"
# Admin Reports API — audit activity (login, admin, drive, ...).
# Live collection needs https://www.googleapis.com/auth/admin.reports.audit.readonly.
REPORTS = "/admin/reports/v1"
GROUPS_SETTINGS = "/groups/v1"

# Cloud Identity and Alert Center use separate hostnames. Absolute URL paths
# are passed directly to httpx; the FixtureTransport maps on the full string.
CLOUD_IDENTITY_BASE = "https://cloudidentity.googleapis.com"
ALERT_CENTER_BASE = "https://alertcenter.googleapis.com"

CUSTOMER = "my_customer"

# Directory / Drive page sizes are API maxima so live walks fewer pages.
USERS_PAGE_SIZE = 500
GROUPS_PAGE_SIZE = 200
MEMBERS_PAGE_SIZE = 200
ROLES_PAGE_SIZE = 200
ASSIGNMENTS_PAGE_SIZE = 200
DRIVES_PAGE_SIZE = 100
PERMISSIONS_PAGE_SIZE = 100
REPORTS_PAGE_SIZE = 1000
POLICIES_PAGE_SIZE = 100
MOBILE_DEVICES_PAGE_SIZE = 100
CHROMEOS_DEVICES_PAGE_SIZE = 100
ALERTS_PAGE_SIZE = 100
SSO_PROFILES_PAGE_SIZE = 50

# Cap page walks so a runaway token loop cannot hang a sync indefinitely.
# Hitting the cap with a remaining token is an error, not a silent truncate.
_MAX_PAGES = 10_000


def users_list_path(*, max_results: int = USERS_PAGE_SIZE) -> str:
    """Customer-wide users (all domains), not the configured primary domain only."""
    return f"{DIRECTORY}/users?customer={CUSTOMER}&maxResults={max_results}"


def groups_list_path(*, max_results: int = GROUPS_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/groups?customer={CUSTOMER}&maxResults={max_results}"


def group_members_path(group_id: str, *, max_results: int = MEMBERS_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/groups/{group_id}/members?maxResults={max_results}"


def roles_list_path(*, max_results: int = ROLES_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/roles?maxResults={max_results}"


def role_assignments_path(*, max_results: int = ASSIGNMENTS_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/roleassignments?maxResults={max_results}"


def drives_list_path(*, page_size: int = DRIVES_PAGE_SIZE) -> str:
    """Domain-admin listing: all shared drives, not only those the subject is in."""
    return f"{DRIVE}/drives?pageSize={page_size}&useDomainAdminAccess=true"


def drive_permissions_path(drive_id: str, *, page_size: int = PERMISSIONS_PAGE_SIZE) -> str:
    return f"{DRIVE}/drives/{drive_id}/permissions?supportsAllDrives=true&useDomainAdminAccess=true&pageSize={page_size}"


def login_activities_path(*, max_results: int = REPORTS_PAGE_SIZE, start_time: str | None = None) -> str:
    """Admin Reports `login` application: sign-in failures, suspicious logins, 2SV changes."""
    path = f"{REPORTS}/activity/users/all/applications/login?maxResults={max_results}"
    if start_time:
        path = f"{path}&startTime={quote(start_time, safe='')}"
    return path


def admin_activities_path(*, max_results: int = REPORTS_PAGE_SIZE, start_time: str | None = None) -> str:
    """Admin Reports `admin` application: privilege grants, SSO changes, DWD client access."""
    path = f"{REPORTS}/activity/users/all/applications/admin?maxResults={max_results}"
    if start_time:
        path = f"{path}&startTime={quote(start_time, safe='')}"
    return path


def drive_activities_path(*, max_results: int = REPORTS_PAGE_SIZE, start_time: str | None = None) -> str:
    """Admin Reports `drive` application: external sharing events."""
    path = f"{REPORTS}/activity/users/all/applications/drive?maxResults={max_results}"
    if start_time:
        path = f"{path}&startTime={quote(start_time, safe='')}"
    return path


def saml_activities_path(*, max_results: int = REPORTS_PAGE_SIZE) -> str:
    """Admin Reports `saml` application: SAML SSO login events."""
    return f"{REPORTS}/activity/users/all/applications/saml?maxResults={max_results}"


def user_accounts_activities_path(*, max_results: int = REPORTS_PAGE_SIZE) -> str:
    """Admin Reports `user_accounts` application: account security events."""
    return f"{REPORTS}/activity/users/all/applications/user_accounts?maxResults={max_results}"


def groups_activities_path(*, max_results: int = REPORTS_PAGE_SIZE) -> str:
    """Admin Reports `groups` application: membership and settings events."""
    return f"{REPORTS}/activity/users/all/applications/groups?maxResults={max_results}"


def mobile_activities_path(*, max_results: int = REPORTS_PAGE_SIZE) -> str:
    """Admin Reports `mobile` application: device enrollment and wipe events."""
    return f"{REPORTS}/activity/users/all/applications/mobile?maxResults={max_results}"


def domain_path(domain: str) -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/domains/{domain}"


def domains_list_path() -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/domains"


def org_units_path() -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/orgunits?type=all"


def user_tokens_path(user_id: str) -> str:
    """OAuth tokens a user has granted to third-party and Google apps."""
    return f"{DIRECTORY}/users/{quote(user_id, safe='')}/tokens"


def group_settings_path(group_email: str) -> str:
    """Groups Settings API (a separate service from the Directory API)."""
    return f"{GROUPS_SETTINGS}/groups/{quote(group_email, safe='')}?alt=json"


def customer_path() -> str:
    """Customer info: ID, domain, creation time."""
    return f"{DIRECTORY}/customers/{CUSTOMER}"


def mobile_devices_path(*, max_results: int = MOBILE_DEVICES_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/devices/mobile?maxResults={max_results}"


def chromeos_devices_path(*, max_results: int = CHROMEOS_DEVICES_PAGE_SIZE) -> str:
    return f"{DIRECTORY}/customer/{CUSTOMER}/devices/chromeos?maxResults={max_results}"


def policies_list_path(*, page_size: int = POLICIES_PAGE_SIZE) -> str:
    """Cloud Identity Policy API — full absolute URL (different host)."""
    return f"{CLOUD_IDENTITY_BASE}/v1/policies?customer=customers/{CUSTOMER}&pageSize={page_size}"


def alerts_list_path(*, page_size: int = ALERTS_PAGE_SIZE) -> str:
    """Alert Center API — full absolute URL (different host)."""
    return f"{ALERT_CENTER_BASE}/v1beta1/alerts?pageSize={page_size}"


def inbound_sso_profiles_path(*, page_size: int = SSO_PROFILES_PAGE_SIZE) -> str:
    """Cloud Identity inbound SAML SSO profiles — full absolute URL."""
    return f"{CLOUD_IDENTITY_BASE}/v1/inboundSamlSsoProfiles?parent=customers/{CUSTOMER}&pageSize={page_size}"


def inbound_sso_assignments_path(*, page_size: int = SSO_PROFILES_PAGE_SIZE) -> str:
    """Cloud Identity inbound SSO OU assignments — full absolute URL."""
    return f"{CLOUD_IDENTITY_BASE}/v1/inboundSsoAssignments?filter=customer%3D%3Dcustomers%2F{CUSTOMER}&pageSize={page_size}"


class GoogleWorkspaceClient:
    def __init__(self, transport: Transport, domain: str) -> None:
        self.transport = transport
        self.domain = domain
        self._users: list[dict[str, Any]] | None = None
        self._groups: list[dict[str, Any]] | None = None
        self._customer_domains: set[str] | None = None

    @staticmethod
    def _items(response: Any, key: str) -> list[dict[str, Any]]:
        """Accepts either a bare list (fixtures) or an Admin SDK envelope
        (live), so the collector never has to care which it got."""
        if isinstance(response, list):
            return response
        if not isinstance(response, dict):
            return []
        return list(response.get(key) or [])

    @staticmethod
    def _with_query(path: str, **params: str) -> str:
        """Merge query params into path, replacing existing keys of the same name."""
        split = urlsplit(path)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        for key, value in params.items():
            if value:
                query[key] = value
            else:
                query.pop(key, None)
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))

    def _list(self, path: str, key: str) -> list[dict[str, Any]]:
        """Walk Google ``nextPageToken`` pagination; fixtures exit after one page.

        Raises PaginationLimitError if the page cap is hit while Google still
        returns a nextPageToken — callers must not treat the result as complete.
        """
        items: list[dict[str, Any]] = []
        page_path = path
        for page_num in range(1, _MAX_PAGES + 1):
            response = self.transport.request("GET", page_path)
            items.extend(self._items(response, key))
            if isinstance(response, list):
                return items
            if not isinstance(response, dict):
                return items
            token = response.get("nextPageToken")
            if not token:
                return items
            if page_num >= _MAX_PAGES:
                raise PaginationLimitError(
                    f"Google Workspace list {path} exceeded {_MAX_PAGES} pages "
                    "with nextPageToken still set; refusing to silently truncate"
                )
            page_path = self._with_query(path, pageToken=str(token))
        raise PaginationLimitError(
            f"Google Workspace list {path} exceeded {_MAX_PAGES} pages "
            "with nextPageToken still set; refusing to silently truncate"
        )

    def get_domain(self) -> dict[str, Any]:
        return self.transport.request("GET", domain_path(self.domain))

    def probe_users(self) -> Any:
        """Single-page health probe (does not walk nextPageToken)."""
        return self.transport.request("GET", users_list_path(max_results=1))

    def probe_groups(self) -> Any:
        return self.transport.request("GET", groups_list_path(max_results=1))

    def probe_roles(self) -> Any:
        return self.transport.request("GET", roles_list_path(max_results=1))

    def probe_shared_drives(self) -> Any:
        return self.transport.request("GET", drives_list_path(page_size=1))

    def probe_login_activities(self) -> Any:
        """Single-page Admin Reports probe (does not walk pages)."""
        return self.transport.request("GET", login_activities_path(max_results=1))

    def list_domains(self) -> list[dict[str, Any]]:
        """Every domain and alias on the customer, primary first."""
        return self._list(domains_list_path(), "domains")

    def customer_domains(self) -> set[str]:
        """Lower-cased domains that count as "inside the tenant": the configured
        primary domain plus every verified domain and alias on the customer.

        Raises when the domains list cannot be read. The collector decides what
        a gate means (reduced coverage, recorded as a skip) and what a transient
        failure means (fail the run); deciding here used to turn a single 429 or
        500 into every alias-domain member being reported as external on a run
        that then went green.
        """
        if self._customer_domains is None:
            names = {self.domain.strip().lower()}
            for row in self.list_domains():
                name = str(row.get("domainName") or "").strip().lower()
                if name:
                    names.add(name)
                for alias in row.get("domainAliases") or []:
                    alias_name = str((alias or {}).get("domainAliasName") or "").strip().lower()
                    if alias_name:
                        names.add(alias_name)
            self._customer_domains = names
        return self._customer_domains

    def list_org_units(self) -> list[dict[str, Any]]:
        return self._list(org_units_path(), "organizationUnits")

    def list_user_tokens(self, user_id: str) -> list[dict[str, Any]]:
        return self._list(user_tokens_path(user_id), "items")

    def get_group_settings(self, group_email: str) -> dict[str, Any]:
        response = self.transport.request("GET", group_settings_path(group_email))
        return dict(response) if isinstance(response, dict) else {}

    def list_users(self) -> list[dict[str, Any]]:
        if self._users is None:
            self._users = self._list(users_list_path(), "users")
        return self._users

    def list_groups(self) -> list[dict[str, Any]]:
        if self._groups is None:
            self._groups = self._list(groups_list_path(), "groups")
        return self._groups

    def list_group_members(self, group_id: str) -> list[dict[str, Any]]:
        return self._list(group_members_path(group_id), "members")

    def list_roles(self) -> list[dict[str, Any]]:
        return self._list(roles_list_path(), "items")

    def list_role_assignments(self) -> list[dict[str, Any]]:
        return self._list(role_assignments_path(), "items")

    def list_shared_drives(self) -> list[dict[str, Any]]:
        return self._list(drives_list_path(), "drives")

    def list_drive_permissions(self, drive_id: str) -> list[dict[str, Any]]:
        return self._list(drive_permissions_path(drive_id), "permissions")

    def list_login_activities(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        """Curated Reports login events. `since` becomes `startTime` (RFC 3339)."""
        start = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z") if since is not None else None
        return self._list(login_activities_path(start_time=start), "items")

    def get_customer(self) -> dict[str, Any]:
        """Directory customer info: ID, primary domain, creation time."""
        response = self.transport.request("GET", customer_path())
        return dict(response) if isinstance(response, dict) else {}

    def list_mobile_devices(self) -> list[dict[str, Any]]:
        return self._list(mobile_devices_path(), "mobiledevices")

    def list_chromeos_devices(self) -> list[dict[str, Any]]:
        return self._list(chromeos_devices_path(), "chromeosdevices")

    def list_policies(self) -> list[dict[str, Any]]:
        """Cloud Identity Policy API (absolute URL — cloudidentity.googleapis.com)."""
        return self._list(policies_list_path(), "policies")

    def list_alerts(self) -> list[dict[str, Any]]:
        """Alert Center API (absolute URL — alertcenter.googleapis.com)."""
        return self._list(alerts_list_path(), "alerts")

    def list_inbound_sso_profiles(self) -> list[dict[str, Any]]:
        """Cloud Identity inbound SAML SSO profiles."""
        return self._list(inbound_sso_profiles_path(), "inboundSamlSsoProfiles")

    def list_inbound_sso_assignments(self) -> list[dict[str, Any]]:
        """Cloud Identity inbound SSO OU assignments."""
        return self._list(inbound_sso_assignments_path(), "inboundSsoAssignments")

    def list_admin_activities(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        start = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z") if since is not None else None
        return self._list(admin_activities_path(start_time=start), "items")

    def list_drive_activity_events(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        start = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z") if since is not None else None
        return self._list(drive_activities_path(start_time=start), "items")

    def list_saml_activities(self) -> list[dict[str, Any]]:
        return self._list(saml_activities_path(), "items")

    def list_user_accounts_activities(self) -> list[dict[str, Any]]:
        return self._list(user_accounts_activities_path(), "items")

    def list_groups_activities(self) -> list[dict[str, Any]]:
        return self._list(groups_activities_path(), "items")

    def list_mobile_activities(self) -> list[dict[str, Any]]:
        return self._list(mobile_activities_path(), "items")
