# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Slack error classification, live auth, and the Test-connection health check.

Exercised through the connector's public surface (`check_health`,
`classify_slack_failure`, `build_live_transport`, `build_audit_transport`)
against a stub transport; nothing touches the network. Probes never return
``ok: false, error: ratelimited`` here because the client backs off with a
real sleep on that path.
"""

from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest
from kestrel_connector_slack.auth import (
    SLACK_API_BASE_URL,
    SLACK_AUDIT_BASE_URL,
    LiveAuthNotConfiguredError,
    build_audit_transport,
    build_live_transport,
)
from kestrel_connector_slack.client import SlackApiError, SlackClient
from kestrel_connector_slack.health import check_health, classify_slack_failure


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://slack.com/api/team.info")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


# -- classification ------------------------------------------------------


@pytest.mark.parametrize("error", ["invalid_auth", "not_authed", "token_revoked", "Token_Expired"])
def test_slack_auth_errors_are_authentication(error: str) -> None:
    assert classify_slack_failure(SlackApiError(error)) == "authentication"


@pytest.mark.parametrize("error", ["missing_scope", "not_an_admin", "feature_not_enabled", "access_denied"])
def test_slack_scope_and_plan_errors_are_permission(error: str) -> None:
    assert classify_slack_failure(SlackApiError(error)) == "permission"


def test_slack_ratelimited_error_is_rate_limit() -> None:
    assert classify_slack_failure(SlackApiError("ratelimited")) == "rate_limit"


def test_other_slack_api_errors_keep_their_code() -> None:
    assert classify_slack_failure(SlackApiError("channel_not_found")) == "api_channel_not_found"


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "authentication"), (403, "permission"), (429, "rate_limit"), (502, "http_502")],
)
def test_http_status_codes_map_to_failure_classes(status: int, expected: str) -> None:
    assert classify_slack_failure(_http_error(status)) == expected


def test_transport_errors_are_network() -> None:
    assert classify_slack_failure(httpx.ConnectTimeout("slow")) == "network"
    assert classify_slack_failure(TimeoutError("slow")) == "network"


def test_a_fixture_mapping_miss_reads_as_permission() -> None:
    class FixtureNotFoundError(Exception):
        pass

    assert classify_slack_failure(FixtureNotFoundError("/admin.teams.list")) == "permission"


def test_an_unrecognized_exception_is_unknown() -> None:
    assert classify_slack_failure(ValueError("???")) == "unknown"


# -- live auth -----------------------------------------------------------


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every host to a public address so URL validation never hits DNS."""

    def fake_getaddrinfo(host: str, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.80.46", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize("secrets", [{}, {"bot_token": ""}, {"other": "x"}])
def test_live_transport_refuses_to_run_without_a_token(secrets: dict[str, str]) -> None:
    with pytest.raises(LiveAuthNotConfiguredError, match="bot_token"):
        build_live_transport(secrets)
    with pytest.raises(LiveAuthNotConfiguredError):
        build_audit_transport(secrets)


@pytest.mark.usefixtures("public_dns")
@pytest.mark.parametrize("key", ["bot_token", "access_token"])
def test_live_transports_carry_the_bearer_token_to_each_host(key: str) -> None:
    web = build_live_transport({key: "xoxp-123"})
    audit = build_audit_transport({key: "xoxp-123"})
    try:
        assert str(web.client.base_url).rstrip("/") == SLACK_API_BASE_URL
        assert str(audit.client.base_url).rstrip("/") == SLACK_AUDIT_BASE_URL
        for transport in (web, audit):
            assert transport.client.headers["Authorization"] == "Bearer xoxp-123"
            assert transport.client.headers["Accept"] == "application/json"
    finally:
        web.client.close()
        audit.client.close()


@pytest.mark.usefixtures("public_dns")
def test_bot_token_wins_over_access_token() -> None:
    transport = build_live_transport({"bot_token": "xoxb-bot", "access_token": "xoxp-user"})
    try:
        assert transport.client.headers["Authorization"] == "Bearer xoxb-bot"
    finally:
        transport.client.close()


# -- health --------------------------------------------------------------


class _StubTransport:
    """Serves a canned body (or raises a canned error) per path substring."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.paths.append(path)
        for needle, value in self.responses.items():
            if needle in path:
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        raise AssertionError("health probes must not paginate")


_CORE = {
    "/team.info": {"ok": True, "team": {"id": "T1"}},
    "/users.list": {"ok": True, "members": []},
    "/usergroups.list": {"ok": True, "usergroups": []},
}
_OPTIONAL = {
    "/admin.apps.approved.list": {"ok": True, "approved_apps": []},
    "/admin.roles.listAssignments": {"ok": True, "role_assignments": []},
    "/admin.teams.list": {"ok": True, "teams": []},
    "/logs": {"entries": []},
    "/admin.barriers.list": {"ok": True, "barriers": []},
    "/admin.workflows.search": {"ok": True, "workflows": []},
    "/admin.analytics.getFile": {"ok": True},
}


def _client(**overrides: Any) -> tuple[SlackClient, _StubTransport]:
    transport = _StubTransport({**_CORE, **_OPTIONAL, **overrides})
    return SlackClient(transport, team_id="T1"), transport


def test_healthy_when_every_probe_succeeds() -> None:
    client, transport = _client()
    client.enterprise_id = "E1"  # an org-level token with its org id set: no notice
    result = check_health(client)
    assert result.healthy is True
    assert result.message == "Slack reachable with all required scopes"
    assert len(result.checked_permissions) == 10
    assert all(result.checked_permissions.values())
    assert all("limit=1" in p or "metadata_only" in p or "team.info" in p for p in transport.paths)


def test_enterprise_probe_failures_degrade_but_stay_healthy() -> None:
    client, _ = _client(
        **{
            "/admin.teams.list": {"ok": False, "error": "not_an_admin"},
            "/logs": _http_error(403),
        }
    )
    result = check_health(client)
    assert result.healthy is True
    assert result.checked_permissions["admin.teams.list"] is False
    assert result.checked_permissions["audit.logs"] is False
    assert "Enterprise inventory partially skipped" in result.message
    assert "admin.teams.list (permission)" in result.message
    assert "audit.logs (permission)" in result.message


def test_audit_probe_uses_the_audit_transport() -> None:
    web = _StubTransport({**_CORE, **_OPTIONAL})
    audit = _StubTransport({"/logs": {"entries": []}})
    client = SlackClient(web, team_id="T1", audit_transport=audit)
    assert check_health(client).healthy is True
    assert audit.paths == ["/logs?limit=1"]
    assert not any(p.startswith("/logs") for p in web.paths)


def test_an_invalid_token_fails_with_an_authentication_message() -> None:
    client, _ = _client(**{"/team.info": {"ok": False, "error": "invalid_auth"}})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Authentication failed (invalid or expired Slack token) for: team.info")


def test_a_missing_core_scope_fails_with_a_permission_message() -> None:
    client, _ = _client(**{"/users.list": {"ok": False, "error": "missing_scope"}})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Permission denied / missing scopes for: users.list (permission)")


def test_core_failures_are_summarised_without_optional_noise() -> None:
    client, _ = _client(
        **{
            "/usergroups.list": _http_error(429),
            "/admin.teams.list": {"ok": False, "error": "not_an_admin"},
        }
    )
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Slack rate-limited for: usergroups.list (rate_limit)")
    assert "admin.teams.list" not in result.message


def test_network_failure_is_reported_as_a_network_error() -> None:
    client, _ = _client(**{"/team.info": httpx.ConnectError("no route")})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Network error reaching Slack for: team.info (network)")


def test_unclassified_core_failures_use_the_generic_message() -> None:
    client, _ = _client(**{"/team.info": {"ok": False, "error": "team_not_found"}})
    result = check_health(client)
    assert result.healthy is False
    assert result.message == "Unreachable or missing scopes for: team.info (api_team_not_found)"
