# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Okta error classification and the Test-connection health check.

Exercised through the connector's public surface (`check_health`,
`classify_okta_failure`, `is_skippable`, `is_rate_limit`) against a stub
transport with canned bodies and errors; nothing touches the network.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kestrel_connector_okta.client import OktaClient
from kestrel_connector_okta.health import check_health
from kestrel_connector_okta.http import (
    classify_okta_failure,
    http_status,
    is_rate_limit,
    is_skippable,
)


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://acme.okta.com/api/v1/users")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


# -- classification ------------------------------------------------------


def test_http_status_reads_the_response_status_or_none() -> None:
    assert http_status(_http_error(418)) == 418
    assert http_status(ValueError("no response")) is None


@pytest.mark.parametrize("status", [403, 404])
def test_permission_and_plan_gates_are_skippable(status: int) -> None:
    assert is_skippable(_http_error(status)) is True


@pytest.mark.parametrize("status", [401, 429, 500])
def test_auth_rate_limit_and_server_errors_are_not_skippable(status: int) -> None:
    assert is_skippable(_http_error(status)) is False


def test_only_429_is_a_rate_limit() -> None:
    assert is_rate_limit(_http_error(429)) is True
    assert is_rate_limit(_http_error(403)) is False


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "authentication"),
        (403, "permission"),
        (429, "rate_limit"),
        (404, "http_404"),
        (503, "http_503"),
    ],
)
def test_status_codes_map_to_failure_classes(status: int, expected: str) -> None:
    assert classify_okta_failure(_http_error(status)) == expected


@pytest.mark.parametrize(
    "exc",
    [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("bad")],
)
def test_httpx_transport_errors_are_network(exc: BaseException) -> None:
    assert classify_okta_failure(exc) == "network"


def test_non_httpx_timeout_and_connect_errors_are_network() -> None:
    assert classify_okta_failure(TimeoutError("slow")) == "network"
    assert classify_okta_failure(ConnectionRefusedError("refused")) == "network"


def test_an_unrecognized_exception_is_unknown() -> None:
    assert classify_okta_failure(ValueError("???")) == "unknown"


# -- health --------------------------------------------------------------


class _StubTransport:
    """Serves a canned body (or raises a canned error) per path prefix."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.paths.append(path)
        for prefix, value in self.responses.items():
            if path.startswith(prefix):
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        raise AssertionError("health probes must not paginate")


def _ok(**overrides: Any) -> dict[str, Any]:
    responses: dict[str, Any] = {
        "/api/v1/org": {"id": "org1"},
        "/api/v1/users/00u1/roles": [],
        "/api/v1/users?": [{"id": "00u1"}],
        "/api/v1/groups?": [],
        "/api/v1/apps?": [],
        "/api/v1/logs?": [],
    }
    responses.update(overrides)
    return responses


def _client(responses: dict[str, Any]) -> tuple[OktaClient, _StubTransport]:
    transport = _StubTransport(responses)
    return OktaClient(transport, org_url="https://acme.okta.com/"), transport


def test_healthy_when_every_probe_succeeds() -> None:
    client, transport = _client(_ok())
    result = check_health(client)
    assert result.healthy is True
    assert result.message == "Okta reachable with required API access"
    assert result.checked_permissions == {
        "org.settings": True,
        "users.list": True,
        "users.roles": True,
        "groups.list": True,
        "apps.list": True,
        "logs.list": True,
    }
    # Every probe is a single page; the first user's roles are checked.
    assert "/api/v1/users/00u1/roles?limit=1" in transport.paths
    assert all("limit=1" in p for p in transport.paths if p != "/api/v1/org")


def test_role_probe_is_skipped_when_the_org_has_no_users() -> None:
    client, transport = _client(_ok(**{"/api/v1/users?": []}))
    result = check_health(client)
    assert result.healthy is True
    assert result.checked_permissions["users.roles"] is True
    assert not any("/roles" in p for p in transport.paths)


@pytest.mark.parametrize(
    "users_body",
    [{"users": [{"id": "00u1"}]}, {"id": "00u1"}],
    ids=["enveloped", "single-object"],
)
def test_first_user_is_found_in_non_list_bodies(users_body: Any) -> None:
    client, transport = _client(_ok(**{"/api/v1/users?": users_body}))
    assert check_health(client).healthy is True
    assert "/api/v1/users/00u1/roles?limit=1" in transport.paths


def test_a_scalar_users_body_skips_the_role_probe() -> None:
    client, transport = _client(_ok(**{"/api/v1/users?": "unexpected"}))
    assert check_health(client).healthy is True
    assert not any("/roles" in p for p in transport.paths)


def test_a_role_read_denial_fails_with_a_permission_message() -> None:
    client, _ = _client(_ok(**{"/api/v1/users/00u1/roles": _http_error(403)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.checked_permissions["users.roles"] is False
    assert result.message.startswith("Permission denied for: users.roles (permission)")


def test_a_failed_user_list_also_fails_the_role_probe() -> None:
    client, _ = _client(_ok(**{"/api/v1/users?": _http_error(401)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.checked_permissions["users.list"] is False
    assert result.checked_permissions["users.roles"] is False
    assert "Authentication failed" in result.message
    assert "users.list (authentication)" in result.message
    assert "users.roles (authentication)" in result.message


def test_authentication_is_reported_ahead_of_permission() -> None:
    client, _ = _client(_ok(**{"/api/v1/org": _http_error(401), "/api/v1/apps?": _http_error(403)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Authentication failed")


@pytest.mark.parametrize("klass_status", [403, 404])
def test_an_unreadable_system_log_degrades_rather_than_failing(klass_status: int) -> None:
    client, _ = _client(_ok(**{"/api/v1/logs?": _http_error(klass_status)}))
    result = check_health(client)
    assert result.healthy is True
    assert result.checked_permissions["logs.list"] is False
    assert "System Log unavailable" in result.message


def test_a_bad_credential_on_the_system_log_still_fails() -> None:
    client, _ = _client(_ok(**{"/api/v1/logs?": _http_error(401)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Authentication failed")


def test_a_rate_limited_probe_is_reported_as_a_rate_limit() -> None:
    client, _ = _client(_ok(**{"/api/v1/groups?": _http_error(429)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Okta rate limit hit for: groups.list (rate_limit)")


def test_network_failure_is_reported_as_a_network_error() -> None:
    client, _ = _client(_ok(**{"/api/v1/org": httpx.ConnectError("no route")}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Network error reaching Okta for: org.settings (network)")


def test_server_errors_are_reported_as_an_api_error() -> None:
    client, _ = _client(_ok(**{"/api/v1/apps?": _http_error(500)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message == "Okta API error for: apps.list (http_500)"


def test_mixed_network_and_http_failures_use_the_generic_message() -> None:
    client, _ = _client(_ok(**{"/api/v1/org": httpx.ConnectError("no route"), "/api/v1/apps?": _http_error(500)}))
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Unreachable or missing access for:")
