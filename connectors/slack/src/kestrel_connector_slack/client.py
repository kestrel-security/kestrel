# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Thin typed wrapper over a Transport for Slack Web API methods.

Every method builds a `path` (including query string) that doubles as the
request signature FixtureTransport matches on. Slack wraps most list
responses as `{"ok": true, "<key>": [...]}`; `_list` walks
``response_metadata.next_cursor`` on live envelopes. Fixtures store the
unwrapped collection (complete result set, one page).

Admin methods that are POST (form body) still encode identifying params in
the path query so fixtures stay exact-match.

Hitting the page cap with a remaining cursor raises — inventory is never
silently truncated. ``ok: false`` ``ratelimited`` retries with backoff
(Slack often returns HTTP 200 rather than 429).

Audit Logs use a separate host (`api.slack.com/audit/v1`); pass
``audit_transport`` for live, or reuse the fixture transport in CI.
"""

from __future__ import annotations

import gzip
import json
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from kestrel.connectors.sdk.base import RawResponse, Transport, request_raw

_MAX_PAGES = 500
_MAX_RATELIMIT_RETRIES = 3
# Longest a `Retry-After` may hold a worker before the run fails instead.
_MAX_RETRY_AFTER_SECONDS = 60.0
_GZIP_MAGIC = b"\x1f\x8b"
PAGE_LIMIT = 200
AUDIT_PAGE_LIMIT = 200
# admin.conversations.search rejects limits outside 1–20.
CONVERSATIONS_SEARCH_LIMIT = 20


class SlackApiError(RuntimeError):
    """Raised when Slack returns HTTP 200 with ``ok: false``."""

    def __init__(self, error: str, *, response: Any | None = None) -> None:
        super().__init__(f"Slack API error: {error}")
        self.error = error
        self.response = response


class SlackPaginationError(RuntimeError):
    """Raised when cursor pagination would otherwise truncate the result set."""


# ``ok: false`` errors that mean "this token or plan cannot read this family".
# A family that answers one of these is recorded as reduced coverage and the
# rest of the sync continues. ``ratelimited`` is deliberately absent: an
# exhausted retry must never look like a tenant with nothing to show.
SKIPPABLE_ADMIN_ERRORS = frozenset(
    {
        "missing_scope",
        "not_allowed",
        "not_an_admin",
        "no_permission",
        "restricted_action",
        "not_allowed_token_type",
        "feature_not_enabled",
        "enterprise_is_restricted",
        "team_access_not_granted",
        "app_management_app_not_installed_on_org",
        "access_denied",
        "ekm_access_denied",
        "unknown_method",
        "not_found",
        "team_not_found",
    }
)


def is_skippable_admin_error(exc: BaseException) -> bool:
    if isinstance(exc, SlackApiError):
        return exc.error in SKIPPABLE_ADMIN_ERRORS
    status = getattr(getattr(exc, "response", None), "status_code", None)
    return status in {403, 404}


class SlackClient:
    def __init__(
        self,
        transport: Transport,
        team_id: str,
        *,
        enterprise_id: str | None = None,
        audit_transport: Transport | None = None,
    ) -> None:
        self.transport = transport
        self.audit_transport = audit_transport or transport
        self.team_id = team_id
        self.enterprise_id = enterprise_id or None
        self._users_cache: list[dict[str, Any]] | None = None
        self._usergroups_cache: list[dict[str, Any]] | None = None
        self._workspaces_cache: list[dict[str, Any]] | None = None
        self._channels_cache: list[dict[str, Any]] | None = None
        self._role_assignments_cache: list[dict[str, Any]] | None = None
        # Set when the org-wide directory walk was gated and `list_users` fell
        # back to the configured workspace alone. The collector records it as
        # reduced coverage; a narrowed directory on a green run would otherwise
        # tombstone every other workspace's users.
        self.org_directory_fallback: BaseException | None = None

    @staticmethod
    def _items(response: Any, key: str) -> list[dict[str, Any]]:
        if isinstance(response, list):
            return response
        if not isinstance(response, dict):
            return []
        return list(response.get(key) or [])

    @staticmethod
    def _with_query(path: str, **params: str) -> str:
        split = urlsplit(path)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        for key, value in params.items():
            if value:
                query[key] = value
            else:
                query.pop(key, None)
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))

    def _admin_apps_query(self, *, limit: int) -> str:
        # enterprise_id and team_id cannot be used together (Slack Admin Apps).
        if self.enterprise_id:
            return f"enterprise_id={self.enterprise_id}&limit={limit}"
        return f"team_id={self.team_id}&limit={limit}"

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        transport: Transport | None = None,
    ) -> Any:
        delay = 1.0
        last_error: SlackApiError | None = None
        client = transport or self.transport
        for attempt in range(_MAX_RATELIMIT_RETRIES + 1):
            kwargs: dict[str, Any] = {}
            if data is not None:
                kwargs["data"] = data
            raw = request_raw(client, method, path, **kwargs)
            response = raw.json()
            if isinstance(response, dict) and response.get("ok") is False:
                error = str(response.get("error") or "unknown_error")
                last_error = SlackApiError(error, response=response)
                if error == "ratelimited" and attempt < _MAX_RATELIMIT_RETRIES:
                    # Slack often answers HTTP 200 for this and names the wait
                    # in Retry-After; the fixed ladder is the fallback.
                    time.sleep(_retry_after(raw) or delay)
                    delay = min(delay * 2, 8.0)
                    continue
                raise last_error
            return response
        raise last_error or SlackApiError("ratelimited")

    def _list(
        self,
        path: str,
        key: str,
        *,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        transport: Transport | None = None,
    ) -> list[dict[str, Any]]:
        """Walk Slack cursor pagination; fixtures exit after one page.

        Raises ``SlackPaginationError`` if a next cursor remains after
        ``_MAX_PAGES`` so callers never treat a partial list as complete.
        """
        items: list[dict[str, Any]] = []
        page_path = path
        page_data = dict(data) if data else None
        for _ in range(_MAX_PAGES):
            response = self._request(page_path, method=method, data=page_data, transport=transport)
            items.extend(self._items(response, key))
            if isinstance(response, list):
                return items
            if not isinstance(response, dict):
                return items
            meta = response.get("response_metadata") or {}
            cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
            # admin.conversations.search returns next_cursor at the top level.
            if not cursor:
                cursor = response.get("next_cursor")
            if not cursor:
                return items
            page_path = self._with_query(path, cursor=str(cursor))
            if page_data is not None:
                page_data = {**page_data, "cursor": str(cursor)}
        raise SlackPaginationError(
            f"Slack cursor pagination exceeded {_MAX_PAGES} pages for {path}; refusing to silently truncate inventory"
        )

    def get_team(self) -> dict[str, Any]:
        response = self._request(f"/team.info?team={self.team_id}")
        if isinstance(response, dict) and "team" in response:
            return dict(response["team"])
        return dict(response) if isinstance(response, dict) else {}

    def _users_list_path(self, *, limit: int) -> str:
        # Org-installed user tokens require team_id; workspace tokens ignore it.
        return f"/users.list?team_id={self.team_id}&limit={limit}"

    def _usergroups_list_path(self, *, limit: int) -> str:
        return f"/usergroups.list?team_id={self.team_id}&include_users=false&limit={limit}"

    def probe_users(self) -> Any:
        return self._request(self._users_list_path(limit=1))

    def probe_usergroups(self) -> Any:
        return self._request(self._usergroups_list_path(limit=1))

    def probe_approved_apps(self) -> Any:
        return self._request(f"/admin.apps.approved.list?{self._admin_apps_query(limit=1)}")

    def probe_role_assignments(self) -> Any:
        return self._request("/admin.roles.listAssignments?limit=1")

    def probe_workspaces(self) -> Any:
        return self._request("/admin.teams.list?limit=1")

    def probe_audit_logs(self) -> Any:
        return self._request(
            "/logs?limit=1",
            transport=self.audit_transport,
        )

    def list_users(self) -> list[dict[str, Any]]:
        if self._users_cache is not None:
            return self._users_cache
        if self.enterprise_id:
            # Prefer org-wide admin.users.list per workspace; fall back to
            # workspace users.list only when Admin Users is *gated*. A throttle
            # or any other failure raises: silently narrowing the directory to
            # one workspace reads as every other workspace's users having left.
            try:
                users = self._list_org_users()
                self._users_cache = users
                return users
            except Exception as exc:
                if not is_skippable_admin_error(exc):
                    raise
                self.org_directory_fallback = exc
        self._users_cache = self._list(self._users_list_path(limit=PAGE_LIMIT), "members")
        return self._users_cache

    def _list_org_users(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for workspace in self.list_workspaces():
            team_id = str(workspace.get("id") or "")
            if not team_id:
                continue
            path = f"/admin.users.list?team_id={team_id}&limit={PAGE_LIMIT}"
            for user in self._list(path, "users"):
                user_id = str(user.get("id") or "")
                if user_id and user_id not in seen:
                    payload = dict(user)
                    payload.setdefault("team_id", team_id)
                    seen[user_id] = payload
        if seen:
            return list(seen.values())
        # admin.users.list can return empty before the app is granted to a
        # workspace; users.list then fails with team_access_not_granted.
        try:
            return self._list(self._users_list_path(limit=PAGE_LIMIT), "members")
        except SlackApiError as exc:
            if exc.error == "team_access_not_granted":
                raise RuntimeError(
                    "Slack API error: team_access_not_granted — the org-installed "
                    f"app is not granted access to workspace {self.team_id}. In "
                    "Slack Org Admin → Integrations → Installed Apps → your app → "
                    "Manage → Add to more workspaces (include this team_id), then "
                    "Sync again."
                ) from exc
            raise

    def list_usergroups(self) -> list[dict[str, Any]]:
        if self._usergroups_cache is not None:
            return self._usergroups_cache
        self._usergroups_cache = self._list(
            self._usergroups_list_path(limit=PAGE_LIMIT),
            "usergroups",
        )
        return self._usergroups_cache

    def list_usergroup_users(self, usergroup_id: str) -> list[str]:
        # Org tokens require team_id (same as usergroups.list / users.list).
        path = f"/usergroups.users.list?usergroup={usergroup_id}&team_id={self.team_id}&limit={PAGE_LIMIT}"
        user_ids: list[str] = []
        page_path = path
        for _ in range(_MAX_PAGES):
            response = self._request(page_path)
            if isinstance(response, list):
                user_ids.extend(str(uid) for uid in response)
                return user_ids
            if not isinstance(response, dict):
                return user_ids
            user_ids.extend(str(uid) for uid in (response.get("users") or []))
            meta = response.get("response_metadata") or {}
            cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
            if not cursor:
                return user_ids
            page_path = self._with_query(path, cursor=str(cursor))
        raise SlackPaginationError(
            f"Slack cursor pagination exceeded {_MAX_PAGES} pages for {path}; "
            "refusing to silently truncate usergroup membership"
        )

    def list_approved_apps(self) -> list[dict[str, Any]]:
        return self._list(
            f"/admin.apps.approved.list?{self._admin_apps_query(limit=PAGE_LIMIT)}",
            "approved_apps",
        )

    def list_restricted_apps(self) -> list[dict[str, Any]]:
        return self._list(
            f"/admin.apps.restricted.list?{self._admin_apps_query(limit=PAGE_LIMIT)}",
            "restricted_apps",
        )

    def list_app_requests(self) -> list[dict[str, Any]]:
        return self._list(
            f"/admin.apps.requests.list?{self._admin_apps_query(limit=PAGE_LIMIT)}",
            "app_requests",
        )

    def list_app_activities(self) -> list[dict[str, Any]]:
        """Recent app activity for last-used signals (Enterprise Grid)."""
        return self._list(
            f"/admin.apps.activities.list?{self._admin_apps_query(limit=PAGE_LIMIT)}",
            "activities",
        )

    def list_channels(self) -> list[dict[str, Any]]:
        """Every public and private channel the token can see (``conversations.list``).

        Works on a bot token (``channels:read`` + ``groups:read``) and on an
        org-installed user token alike; archived channels are excluded because
        nobody can be added to them. Slack Connect channels appear here with
        ``is_ext_shared``; the Grid-only ``admin.conversations.search`` family
        remains the source for the external organizations behind them.
        """
        if self._channels_cache is None:
            self._channels_cache = self._list(
                f"/conversations.list?types=public_channel%2Cprivate_channel&exclude_archived=true&limit={PAGE_LIMIT}",
                "channels",
            )
        return self._channels_cache

    def list_channel_members(self, channel_id: str) -> list[str]:
        """Member user ids of one channel (``conversations.members``)."""
        members: list[str] = []
        path = f"/conversations.members?channel={channel_id}&limit={PAGE_LIMIT}"
        page_path = path
        for _ in range(_MAX_PAGES):
            response = self._request(page_path)
            if isinstance(response, dict):
                members.extend(str(m) for m in response.get("members") or [])
                meta = response.get("response_metadata") or {}
                cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
                if not cursor:
                    return members
                page_path = self._with_query(path, cursor=str(cursor))
                continue
            if isinstance(response, list):
                members.extend(str(m) for m in response)
            return members
        raise SlackPaginationError(
            f"Slack cursor pagination exceeded {_MAX_PAGES} pages for {path}; refusing to silently truncate membership"
        )

    def list_workspaces(self) -> list[dict[str, Any]]:
        if self._workspaces_cache is not None:
            return self._workspaces_cache
        self._workspaces_cache = self._list(f"/admin.teams.list?limit={PAGE_LIMIT}", "teams")
        return self._workspaces_cache

    # Slack applies session settings per user, not per workspace: there is no
    # workspace-level session field on `team.info` or `admin.teams.settings.info`.
    # The method takes a batch of user ids, so this is a handful of calls for a
    # whole directory rather than one per user.
    SESSION_SETTINGS_BATCH = 200

    def get_session_settings(self, user_ids: list[str]) -> list[dict[str, Any]]:
        """`admin.users.session.getSettings` for a batch of users.

        Users with no explicit settings come back under `no_settings_applied`
        and are simply absent from the result -- that is "Slack's default", not
        "unknown", but the connector does not guess which, so they get no row.
        """
        out: list[dict[str, Any]] = []
        for start in range(0, len(user_ids), self.SESSION_SETTINGS_BATCH):
            batch = user_ids[start : start + self.SESSION_SETTINGS_BATCH]
            response = self._request(
                "/admin.users.session.getSettings",
                method="POST",
                data={"user_ids": batch},
            )
            if isinstance(response, dict):
                out.extend(row for row in response.get("session_settings") or [] if isinstance(row, dict))
        return out

    def get_workspace_settings(self, team_id: str) -> dict[str, Any]:
        path = f"/admin.teams.settings.info?team_id={team_id}"
        response = self._request(path, method="POST", data={"team_id": team_id})
        if isinstance(response, dict) and "team" in response:
            return dict(response["team"])
        return dict(response) if isinstance(response, dict) else {}

    def list_role_assignments(self) -> list[dict[str, Any]]:
        if self._role_assignments_cache is not None:
            return self._role_assignments_cache
        self._role_assignments_cache = self._list(
            f"/admin.roles.listAssignments?limit={PAGE_LIMIT}",
            "role_assignments",
        )
        return self._role_assignments_cache

    def list_external_teams(self) -> list[dict[str, Any]]:
        return self._list(
            f"/team.externalTeams.list?limit={PAGE_LIMIT}",
            "organizations",
        )

    def list_shared_channels(self) -> list[dict[str, Any]]:
        """Externally shared / Slack Connect channels only (not full inventory).

        Uses ``team_ids`` (workspace ``T…``), not ``enterprise_id``. Limit max
        is 20 per Slack docs — do not reuse ``PAGE_LIMIT``.
        """
        limit = CONVERSATIONS_SEARCH_LIMIT
        path = f"/admin.conversations.search?team_ids={self.team_id}&limit={limit}&search_channel_types=external_shared"
        data = {
            "team_ids": self.team_id,
            "limit": str(limit),
            "search_channel_types": "external_shared",
        }
        return self._list(path, "conversations", method="POST", data=data)

    def get_anomaly_allowlist(self) -> dict[str, Any]:
        path = "/admin.audit.anomaly.allow.getItem"
        response = self._request(path, method="POST", data={})
        return dict(response) if isinstance(response, dict) else {}

    def list_audit_logs(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        """Curated Audit Logs poll. Live uses audit host; fixtures share mapping.

        ``since`` maps to the Audit Logs ``oldest`` cursor so incremental syncs
        only fetch events after the last sync timestamp.  The fixture transport
        strips ``oldest`` (declared in ``volatile_params``) so CI sees the full
        fixture regardless of wall time.
        """
        path = f"/logs?limit={AUDIT_PAGE_LIMIT}"
        if since is not None:
            stamp = int(since.astimezone(UTC).timestamp())
            path = f"{path}&oldest={stamp}"
        return self._list(path, "entries", transport=self.audit_transport)

    # ------------------------------------------------------------------ #
    # Release C — Enterprise depth families                                #
    # ------------------------------------------------------------------ #

    def probe_information_barriers(self) -> Any:
        return self._request("/admin.barriers.list?limit=1")

    def probe_workflows(self) -> Any:
        return self._request("/admin.workflows.search?limit=1")

    def probe_analytics(self) -> Any:
        return self._request("/admin.analytics.getFile?type=member&metadata_only=true")

    def get_auth_policy(self) -> dict[str, Any]:
        """SSO/email-password policy assignments (admin.auth.policy.getEntities).

        Returns the raw response; the collector interprets ``entities`` to decide
        whether SSO bypass is possible.  Enterprise Grid + admin.auth.policy:read.
        """
        response = self._request("/admin.auth.policy.getEntities", method="POST", data={})
        return dict(response) if isinstance(response, dict) else {}

    def list_information_barriers(self) -> list[dict[str, Any]]:
        """Information barriers (admin.barriers.list, Enterprise Grid)."""
        return self._list(f"/admin.barriers.list?limit={PAGE_LIMIT}", "barriers")

    def list_workflows(self) -> list[dict[str, Any]]:
        """Workflow inventory (admin.workflows.search, Enterprise Grid)."""
        return self._list(f"/admin.workflows.search?limit={PAGE_LIMIT}", "workflows")

    def get_channel_retention(self, channel_id: str) -> dict[str, Any] | None:
        """Custom retention for one channel (admin.conversations.getCustomRetention).

        Returns the Slack response dict (a channel without a custom policy
        answers ``ok: true`` with the policy disabled). Errors raise so the
        collector can tell "no custom retention" from "could not read it".
        """
        response = self._request(
            "/admin.conversations.getCustomRetention",
            method="POST",
            data={"channel_id": channel_id},
        )
        return dict(response) if isinstance(response, dict) else None

    def list_invite_requests(self) -> list[dict[str, Any]]:
        """Pending invite requests (admin.invites.invited.list, Enterprise Grid)."""
        path = f"/admin.invites.invited.list?limit={PAGE_LIMIT}"
        if self.enterprise_id:
            path = f"{path}&enterprise_id={self.enterprise_id}"
        return self._list(path, "invite_requests")

    def get_member_analytics(self) -> list[dict[str, Any]]:
        """Member analytics (admin.analytics.getFile?type=member, Enterprise Grid).

        A successful live response is a **gzipped NDJSON file**, one member
        record per line, not a JSON envelope -- the ``metadata_only`` probe the
        health check uses is the only JSON shape this method has. A gated
        tenant answers ``ok: false`` JSON, which raises `SlackApiError` like
        any other method. Returns per-member records carrying
        ``date_last_active``; used to augment user dormancy beyond Audit Logs.
        """
        raw = request_raw(self.transport, "GET", "/admin.analytics.getFile?type=member")
        return parse_member_analytics(raw)


def _retry_after(raw: RawResponse) -> float | None:
    value = str(raw.headers.get("retry-after", "")).strip()
    if not value.isdigit():
        return None
    return min(float(value), _MAX_RETRY_AFTER_SECONDS)


def parse_member_analytics(raw: RawResponse) -> list[dict[str, Any]]:
    """Member records from an analytics export body.

    Accepts the live shape (gzip of newline-delimited JSON objects), plain
    NDJSON, a JSON list, or a JSON envelope (``members`` / ``analytics``, the
    fixture shape). An ``ok: false`` envelope raises `SlackApiError` so the
    gate is classified like any other admin call.
    """
    content = raw.content
    if content.startswith(_GZIP_MAGIC):
        content = gzip.decompress(content)
    text = content.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        parsed: Any = json.loads(text)
    except ValueError:
        parsed = None
    if parsed is None:
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                records.append(row)
        return records
    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    if isinstance(parsed, dict):
        if parsed.get("ok") is False:
            raise SlackApiError(str(parsed.get("error") or "unknown_error"), response=parsed)
        members = parsed.get("members") or parsed.get("analytics") or []
        return [row for row in members if isinstance(row, dict)] if isinstance(members, list) else []
    return []
