# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for GitHub error classification and the health check.

`health.py` previously hardcoded `healthy=True` and a fabricated
`{"read:org": True}`, so Test connection could not fail and reported a
permission it never probed. These tests pin the replacement: real probes,
GitHub's 403-shaped rate limit, and the audit log degrading rather than
failing on plans that do not expose it.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kestrel_connector_github.client import GitHubClient
from kestrel_connector_github.health import check_health
from kestrel_connector_github.http import (
    classify_github_failure,
    is_rate_limit,
    is_skippable,
)


def _http_error(status: int, headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.github.com/orgs/acme")
    response = httpx.Response(status, headers=headers or {}, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


# -- classification ------------------------------------------------------


@pytest.mark.parametrize("status", [403, 404])
def test_permission_and_missing_resources_are_skippable(status: int) -> None:
    assert is_skippable(_http_error(status)) is True


@pytest.mark.parametrize("status", [401, 500, 502])
def test_auth_and_server_errors_are_not_skippable(status: int) -> None:
    assert is_skippable(_http_error(status)) is False


def test_a_primary_rate_limit_403_is_a_rate_limit_not_a_permission_error() -> None:
    exc = _http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})
    assert is_rate_limit(exc) is True
    assert classify_github_failure(exc) == "rate_limit"


def test_a_rate_limited_403_is_never_skipped() -> None:
    # Skipping a throttled object type would report a partial inventory as
    # complete, which change detection then reads as mass deletion.
    exc = _http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})
    assert is_skippable(exc) is False


def test_a_secondary_rate_limit_403_with_retry_after_is_a_rate_limit() -> None:
    exc = _http_error(403, {"retry-after": "30"})
    assert is_rate_limit(exc) is True
    assert is_skippable(exc) is False


def test_a_plain_403_is_a_permission_error() -> None:
    exc = _http_error(403)
    assert is_rate_limit(exc) is False
    assert classify_github_failure(exc) == "permission"


def test_429_is_always_a_rate_limit() -> None:
    assert is_rate_limit(_http_error(429)) is True


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "authentication"), (404, "http_404"), (500, "http_500")],
)
def test_status_codes_map_to_failure_classes(status: int, expected: str) -> None:
    assert classify_github_failure(_http_error(status)) == expected


def test_connection_failures_are_classified_as_network() -> None:
    exc = httpx.ConnectError("no route to host")
    assert classify_github_failure(exc) == "network"


def test_an_unrecognized_exception_is_unknown() -> None:
    assert classify_github_failure(ValueError("???")) == "unknown"


# -- health --------------------------------------------------------------


class _StubTransport:
    """Returns a canned body per path, or raises a canned error."""

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


_ALL_OK = {
    "/orgs/acme/members": [],
    "/orgs/acme/teams": [],
    "/orgs/acme/repos": [],
    "/orgs/acme/audit-log": [],
    "/orgs/acme": {"login": "acme"},
}


def _client(responses: dict[str, Any]) -> GitHubClient:
    return GitHubClient(_StubTransport(responses), org_login="acme")


def test_healthy_when_every_probe_succeeds() -> None:
    result = check_health(_client(_ALL_OK))
    assert result.healthy is True
    assert "acme" in result.message
    assert result.checked_permissions["audit_log.list"] is True


def test_probes_never_walk_pagination() -> None:
    transport = _StubTransport(_ALL_OK)
    check_health(GitHubClient(transport, org_login="acme"))
    assert len(transport.paths) == 6


def test_a_missing_audit_log_degrades_rather_than_failing() -> None:
    # The audit log API is GitHub Enterprise Cloud only. A Team-plan org must
    # still report healthy, with the gap stated plainly.
    result = check_health(_client({**_ALL_OK, "/orgs/acme/audit-log": _http_error(403)}))
    assert result.healthy is True
    assert result.checked_permissions["audit_log.list"] is False
    assert "audit log unavailable" in result.message
    assert "Enterprise Cloud" in result.message


def test_a_bad_credential_on_the_audit_log_still_fails() -> None:
    # 401 there is not a plan gate -- the credential itself is wrong.
    result = check_health(_client({**_ALL_OK, "/orgs/acme/audit-log": _http_error(401)}))
    assert result.healthy is False
    assert "Authentication failed" in result.message


def test_a_missing_required_scope_fails_and_names_the_scope() -> None:
    result = check_health(_client({**_ALL_OK, "/orgs/acme/repos": _http_error(403)}))
    assert result.healthy is False
    assert "repos.list" in result.message
    assert "repo" in result.message


def test_authentication_failure_is_reported_ahead_of_permission() -> None:
    result = check_health(_client({**_ALL_OK, "/orgs/acme": _http_error(401), "/orgs/acme/repos": _http_error(403)}))
    assert result.healthy is False
    assert "Authentication failed" in result.message


def test_a_rate_limited_probe_is_reported_as_a_rate_limit() -> None:
    exc = _http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})
    result = check_health(_client({**_ALL_OK, "/orgs/acme/teams": exc}))
    assert result.healthy is False
    assert "rate limit" in result.message


def test_network_failure_is_reported_as_a_network_error() -> None:
    result = check_health(_client({key: httpx.ConnectError("down") for key in _ALL_OK}))
    assert result.healthy is False
    assert "Network error" in result.message
