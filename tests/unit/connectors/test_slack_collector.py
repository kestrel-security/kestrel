# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for SlackCollector's degradation behaviour.

Everything past members and usergroups is Enterprise Grid territory, so a
workspace-only bot token -- a configuration Kestrel explicitly supports -- gets
a classified admin error for org roles, workspaces, app governance, Connect
orgs, shared channels, and Audit Logs.

all of it returned empty with nothing recorded. The run reported
SUCCESS over an inventory missing every OAuth grant and org-role assignment,
`detect_deletions` read those absences as revocations, and `/changes` filled
with access removals that never happened.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from kestrel.connectors.sdk.base import RawResponse
from kestrel_connector_slack.client import SlackApiError, SlackClient
from kestrel_connector_slack.collector import SlackCollector

TEAM = "T0ACME"


def _slack_error(error: str) -> SlackApiError:
    return SlackApiError(error)


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://slack.com/api/x")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class _CannedTransport:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        for prefix, value in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(prefix):
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        yield self.request(method, path, **kwargs)


_USER = {
    "id": "U1",
    "name": "ada",
    "is_admin": True,
    "has_2fa": True,
    "profile": {"email": "ada@acme.test"},
    "updated": 1735689600,
}
# Live Admin Apps shape: the app nests under "app" and the installer comes from
# last_resolved_by.actor_id (see apps.flatten_approved_app).
_APP = {
    "app": {"id": "A1", "name": "Jira", "developer_type": "third_party"},
    "scopes": [{"name": "channels:read", "is_sensitive": False, "token_type": "bot"}],
    "last_resolved_by": {"actor_id": "U1"},
    "date_updated": 1735689600,
}

_BASE: dict[str, Any] = {
    "/team.info": {"team": {"id": TEAM, "name": "Acme", "domain": "acme"}},
    "/users.list": {"members": [_USER]},
    "/usergroups.list": {"usergroups": [{"id": "S1", "name": "Security", "handle": "sec"}]},
    "/usergroups.users.list": {"users": ["U1"]},
    "/admin.apps.approved.list": {"approved_apps": [_APP]},
    "/admin.apps.restricted.list": {"restricted_apps": []},
    "/admin.apps.requests.list": {"app_requests": []},
    "/admin.apps.activities.list": {"activities": []},
    "/admin.teams.list": {"teams": [{"id": TEAM, "name": "Acme"}]},
    "/admin.teams.settings.info": {"team": {"id": TEAM, "name": "Acme"}},
    "/admin.roles.listAssignments": {"role_assignments": []},
    "/team.externalTeams.list": {"external_teams": []},
    "/admin.conversations.search": {"conversations": []},
    "/admin.audit.anomaly.allow.getItem": {"trusted_ip_list": []},
    "/admin.users.session.getSettings": {
        "session_settings": [{"user_id": "U1", "duration": 43200, "desktop_app_browser_quit": True}],
        "no_settings_applied": [],
    },
    "/logs": {"entries": []},
    "/conversations.list": {
        "channels": [
            {"id": "C1", "name": "general", "is_private": False, "num_members": 2},
            {"id": "C2", "name": "secret", "is_private": True, "num_members": 2},
            {"id": "C3", "name": "ext", "is_private": False, "is_ext_shared": True, "num_members": 2},
        ]
    },
    "/conversations.members?channel=C2": {"members": ["U1", "U9"]},
    "/conversations.members?channel=C3": {"members": ["U1"]},
    # Release C — Enterprise depth families.
    "/admin.auth.policy.getEntities": {"ok": True, "policies": []},
    "/admin.barriers.list": {"ok": True, "barriers": []},
    "/admin.workflows.search": {"ok": True, "workflows": []},
    "/admin.conversations.getCustomRetention": {"ok": True, "type": "custom", "duration": 90},
    "/admin.invites.invited.list": {"ok": True, "invite_requests": []},
    "/admin.analytics.getFile": [],
}


def _collector(overrides: dict[str, Any] | None = None) -> tuple[SlackCollector, _CannedTransport]:
    transport = _CannedTransport({**_BASE, **(overrides or {})})
    return SlackCollector(SlackClient(transport, team_id=TEAM)), transport


def _drain(collector: SlackCollector) -> dict[str, int]:
    return {object_type: len(list(collector.collect(object_type))) for object_type in collector.discover()}


def test_a_full_run_records_no_skips() -> None:
    collector, _ = _collector()
    counts = _drain(collector)
    assert counts["user"] == 1
    assert counts["usergroup"] == 1
    assert counts["oauth_app"] == 1
    assert collector.skipped_object_types == {}


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("workspace", "/admin.teams.list"),
        ("org_role", "/admin.roles.listAssignments"),
        ("restricted_app", "/admin.apps.restricted.list"),
        ("app_request", "/admin.apps.requests.list"),
        ("external_team", "/team.externalTeams.list"),
        ("shared_channel", "/admin.conversations.search"),
        ("anomaly_allowlist", "/admin.audit.anomaly.allow.getItem"),
        ("user_session_setting", "/admin.users.session.getSettings"),
        ("audit_log", "/logs"),
    ],
)
def test_a_grid_gated_family_is_recorded_not_swallowed(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _slack_error("missing_scope")})
    assert list(collector.collect(object_type)) == []
    assert collector.skipped_object_types == {object_type: "permission"}


def test_a_workspace_only_token_still_collects_the_workspace_it_can_see() -> None:
    # The whole point of degradation: members and usergroups are real data even
    # when every Grid family is gated.
    gated = dict.fromkeys(
        [
            "/conversations.list",
            "/admin.apps.approved.list",
            "/admin.apps.restricted.list",
            "/admin.apps.requests.list",
            "/admin.teams.list",
            "/admin.roles.listAssignments",
            "/team.externalTeams.list",
            "/admin.conversations.search",
            "/admin.audit.anomaly.allow.getItem",
            "/logs",
            # Release C families.
            "/admin.auth.policy.getEntities",
            "/admin.barriers.list",
            "/admin.workflows.search",
            "/admin.invites.invited.list",
            "/admin.analytics.getFile",
        ],
        _slack_error("not_an_admin"),
    )
    collector, _ = _collector(gated)
    counts = _drain(collector)
    assert counts["user"] == 1
    assert counts["usergroup"] == 1
    assert counts["role_assignment"] == 1
    assert counts["oauth_app"] == 0
    assert counts["workspace"] == 0
    # Every gated family named, so the operator sees what is missing rather than
    # a green run over half a tenant.
    assert set(collector.skipped_object_types) == {
        "oauth_app.approved",
        "restricted_app",
        "app_request",
        "workspace",
        "org_role",
        "org_role_assignment",
        "external_team",
        "shared_channel",
        "anomaly_allowlist",
        "audit_log",
        "channel",
        # Sign-in activity is derived from Audit Logs and analytics; when both
        # are gated the operator must see that last-active is a profile timestamp.
        "user.last_login",
        "user.analytics",
        # Release C families.
        "sso_policy",
        "information_barrier",
        "workflow",
        "invite_request",
        "channel_retention",
    }
    assert set(collector.skipped_object_types.values()) == {"permission"}


def test_the_approved_app_gate_is_recorded_once_for_all_three_families() -> None:
    collector, _ = _collector({"/admin.apps.approved.list": _slack_error("missing_scope")})
    assert list(collector.collect("oauth_app")) == []
    assert list(collector.collect("oauth_scope")) == []
    assert list(collector.collect("oauth_grant")) == []
    assert collector.skipped_object_types == {"oauth_app.approved": "permission"}


def test_installer_grants_come_from_the_approved_app_record() -> None:
    # Slack has no installations API; the approved app names its installer.
    collector, transport = _collector()
    grants = list(collector.collect("oauth_grant"))
    assert len(grants) == 1
    assert grants[0].payload["user_id"] == "U1"
    assert collector.skipped_object_types == {}
    assert not any("admin.apps.installations" in call for call in transport.calls)


def test_unreadable_workspace_settings_are_a_sub_family_not_the_whole_family() -> None:
    collector, _ = _collector({"/admin.teams.settings.info": _slack_error("missing_scope")})
    workspaces = list(collector.collect("workspace"))
    assert len(workspaces) == 1  # the workspace list itself was readable
    assert collector.skipped_object_types == {"workspace.settings": "permission"}


def test_a_failure_on_a_core_family_still_fails_the_run() -> None:
    collector, _ = _collector({"/users.list": _slack_error("missing_scope")})
    with pytest.raises(SlackApiError):
        list(collector.collect("user"))
    assert collector.skipped_object_types == {}


def test_a_throttled_family_raises_rather_than_reporting_zero_rows() -> None:
    # `ratelimited` is deliberately absent from SKIPPABLE_ADMIN_ERRORS: an
    # exhausted retry must not look like a tenant with no audit events.
    collector, _ = _collector({"/logs": _slack_error("ratelimited")})
    with pytest.raises(SlackApiError):
        list(collector.collect("audit_log"))
    assert collector.skipped_object_types == {}


def test_an_http_403_is_classified_the_same_as_a_slack_permission_error() -> None:
    collector, _ = _collector({"/admin.teams.list": _http_error(403)})
    assert list(collector.collect("workspace")) == []
    assert collector.skipped_object_types == {"workspace": "permission"}


def test_an_unknown_object_type_is_rejected() -> None:
    collector, _ = _collector()
    with pytest.raises(ValueError, match="does not support object_type"):
        list(collector.collect("nope"))


def test_user_last_login_is_stitched_from_audit_logs() -> None:
    collector, _ = _collector(
        {
            "/logs": {
                "entries": [
                    {"id": "1", "action": "user_login", "date_create": 1735000000, "actor": {"user": {"id": "U1"}}},
                    {"id": "2", "action": "user_login", "date_create": 1736000000, "actor": {"user": {"id": "U1"}}},
                    {
                        "id": "3",
                        "action": "role_change_to_admin",
                        "date_create": 1737000000,
                        "actor": {"user": {"id": "U1"}},
                    },
                ]
            }
        }
    )
    users = list(collector.collect("user"))
    assert users[0].payload["last_login_at"] == 1736000000
    assert "user.last_login" not in collector.skipped_object_types


def test_user_without_a_login_event_carries_no_last_login() -> None:
    collector, _ = _collector()
    users = list(collector.collect("user"))
    assert "last_login_at" not in users[0].payload


def test_channel_membership_is_read_only_for_private_and_shared_channels() -> None:
    collector, transport = _collector()
    by_id = {c.provider_id: c.payload for c in collector.collect("channel")}
    assert "member_ids" not in by_id["C1"]
    # U9 is not in the directory listing and is dropped rather than dangling.
    assert by_id["C2"]["member_ids"] == ["U1"]
    assert by_id["C3"]["member_ids"] == ["U1"]
    assert not any("conversations.members?channel=C1" in call for call in transport.calls)
    assert collector.skipped_object_types == {}


def test_channel_membership_past_the_cap_is_reported_as_truncated() -> None:
    transport = _CannedTransport(dict(_BASE))
    collector = SlackCollector(SlackClient(transport, team_id=TEAM), channel_membership_limit=1)
    by_id = {c.provider_id: c.payload for c in collector.collect("channel")}
    assert "member_ids" in by_id["C2"]
    assert "member_ids" not in by_id["C3"]
    assert collector.skipped_object_types == {"channel.membership.truncated": "channel_membership_limit=1"}


def test_a_gated_membership_call_is_a_sub_family_skip() -> None:
    collector, _ = _collector({"/conversations.members?channel=C2": _slack_error("missing_scope")})
    by_id = {c.provider_id: c.payload for c in collector.collect("channel")}
    assert by_id["C2"]["member_ids"] == []
    assert collector.skipped_object_types == {"channel.members": "permission"}


# -- Enterprise Grid directory fallback ----------------------------------------


def _grid_collector(overrides: dict[str, Any]) -> tuple[SlackCollector, _CannedTransport]:
    transport = _CannedTransport({**_BASE, **overrides})
    return SlackCollector(SlackClient(transport, team_id=TEAM, enterprise_id="E1")), transport


def test_a_gated_org_directory_falls_back_to_the_workspace_and_is_recorded() -> None:
    collector, transport = _grid_collector({"/admin.users.list": _slack_error("missing_scope")})
    users = list(collector.collect("user"))
    assert [u.provider_id for u in users] == ["U1"]
    # The narrowed directory is reduced coverage: a green run here tombstones
    # every other workspace's users, memberships, roles and grants.
    assert collector.skipped_object_types["user.org_directory"] == "permission"
    assert any(call.startswith("/users.list") for call in transport.calls)


def test_a_throttled_org_directory_fails_the_run_rather_than_narrowing_it() -> None:
    collector, _ = _grid_collector({"/admin.users.list": _slack_error("ratelimited")})
    with pytest.raises(SlackApiError, match="ratelimited"):
        list(collector.collect("user"))
    assert collector.skipped_object_types == {}


def test_a_transport_failure_on_the_org_directory_is_not_swallowed() -> None:
    collector, _ = _grid_collector({"/admin.users.list": _http_error(500)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("user"))


def test_the_org_directory_fallback_is_recorded_whichever_family_reads_users_first() -> None:
    collector, _ = _grid_collector({"/admin.users.list": _slack_error("not_an_admin")})
    list(collector.collect("role_assignment"))
    assert collector.skipped_object_types["user.org_directory"] == "permission"


def test_a_healthy_org_directory_records_nothing() -> None:
    collector, _ = _grid_collector({"/admin.users.list": {"users": [{**_USER, "id": "U2"}]}})
    users = list(collector.collect("user"))
    assert [u.provider_id for u in users] == ["U2"]
    assert "user.org_directory" not in collector.skipped_object_types


# -- Member analytics: a gzipped NDJSON export, not JSON ----------------------


class _RawTransport(_CannedTransport):
    """Serves raw bodies for paths in ``raw``; everything else is JSON."""

    def __init__(self, responses: dict[str, Any], raw: dict[str, bytes]) -> None:
        super().__init__(responses)
        self.raw = raw

    def request_raw(self, method: str, path: str, **kwargs: Any) -> RawResponse:
        for prefix, body in self.raw.items():
            if path.startswith(prefix):
                self.calls.append(path)
                return RawResponse(status_code=200, headers={}, content=body)
        return request_raw_fallback(self, method, path, **kwargs)


def request_raw_fallback(transport: _CannedTransport, method: str, path: str, **kwargs: Any) -> RawResponse:
    body = transport.request(method, path, **kwargs)
    return RawResponse(status_code=200, headers={}, content=json.dumps(body).encode())


def _ndjson_gzip(rows: list[dict[str, Any]]) -> bytes:
    return gzip.compress("\n".join(json.dumps(row) for row in rows).encode() + b"\n")


def test_member_analytics_is_read_from_the_gzipped_ndjson_export() -> None:
    export = _ndjson_gzip(
        [
            {"user_id": "U1", "date_last_active": "2026-09-15", "enterprise_id": "E1"},
            {"user_id": "U9", "date_last_active": "2026-01-01"},
        ]
    )
    transport = _RawTransport(dict(_BASE), {"/admin.analytics.getFile": export})
    collector = SlackCollector(SlackClient(transport, team_id=TEAM))
    users = list(collector.collect("user"))
    assert users[0].payload["last_login_at"] == int(datetime(2026, 9, 15, tzinfo=UTC).timestamp())
    assert "user.analytics" not in collector.skipped_object_types


def test_a_gated_analytics_export_is_still_a_classified_skip() -> None:
    body = json.dumps({"ok": False, "error": "feature_not_enabled"}).encode()
    transport = _RawTransport(dict(_BASE), {"/admin.analytics.getFile": body})
    collector = SlackCollector(SlackClient(transport, team_id=TEAM))
    assert len(list(collector.collect("user"))) == 1
    assert collector.skipped_object_types == {"user.analytics": "permission"}


def test_an_undecodable_analytics_export_degrades_the_augmentation_not_the_run() -> None:
    transport = _RawTransport(dict(_BASE), {"/admin.analytics.getFile": b"\x1f\x8b\x00not really gzip"})
    collector = SlackCollector(SlackClient(transport, team_id=TEAM))
    users = list(collector.collect("user"))
    assert len(users) == 1
    assert "user.analytics" in collector.skipped_object_types


def test_a_throttled_analytics_export_degrades_rather_than_failing_the_directory() -> None:
    collector, _ = _collector({"/admin.analytics.getFile": _slack_error("ratelimited")})
    assert len(list(collector.collect("user"))) == 1
    assert collector.skipped_object_types == {"user.analytics": "rate_limit"}


def test_the_fixture_shaped_json_envelope_still_parses() -> None:
    collector, _ = _collector(
        {"/admin.analytics.getFile": {"members": [{"user_id": "U1", "date_last_active": "2026-02-02"}]}}
    )
    users = list(collector.collect("user"))
    assert users[0].payload["last_login_at"] == int(datetime(2026, 2, 2, tzinfo=UTC).timestamp())


# -- Swallowed gates now recorded ---------------------------------------------


def test_a_gated_retention_read_is_recorded_rather_than_read_as_no_policy() -> None:
    collector, _ = _collector({"/admin.conversations.getCustomRetention": _slack_error("missing_scope")})
    assert list(collector.collect("channel_retention")) == []
    assert collector.skipped_object_types == {"channel_retention": "permission"}


def test_a_channel_that_vanished_mid_run_is_an_absence_not_a_skip() -> None:
    collector, _ = _collector({"/admin.conversations.getCustomRetention": _slack_error("channel_not_found")})
    assert list(collector.collect("channel_retention")) == []
    assert collector.skipped_object_types == {}


def test_a_retention_policy_is_collected_when_readable() -> None:
    collector, _ = _collector()
    rows = list(collector.collect("channel_retention"))
    assert len(rows) == 2  # the private and the externally shared channel
    assert collector.skipped_object_types == {}


def test_gated_app_activities_are_recorded_so_unused_app_checks_are_not_silently_blind() -> None:
    collector, _ = _collector({"/admin.apps.activities.list": _slack_error("missing_scope")})
    grants = list(collector.collect("oauth_grant"))
    assert len(grants) == 1
    assert collector.skipped_object_types == {"oauth_grant.activities": "permission"}


# -- Retry-After on ``ok: false, error: ratelimited`` -------------------------


def test_a_ratelimited_envelope_waits_retry_after_rather_than_the_fixed_ladder(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_connector_slack import client as client_module

    slept: list[float] = []
    monkeypatch.setattr(client_module.time, "sleep", slept.append)
    answers = iter(
        [
            RawResponse(200, {"retry-after": "7"}, json.dumps({"ok": False, "error": "ratelimited"}).encode()),
            RawResponse(200, {}, json.dumps({"team": {"id": TEAM}}).encode()),
        ]
    )

    class _Throttling:
        def request(self, method: str, path: str, **kwargs: Any) -> Any:
            raise AssertionError("the raw path should be preferred")

        def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
            yield from ()

        def request_raw(self, method: str, path: str, **kwargs: Any) -> RawResponse:
            return next(answers)

    client = SlackClient(_Throttling(), team_id=TEAM)  # type: ignore[arg-type]
    assert client.get_team() == {"id": TEAM}
    assert slept == [7.0]
