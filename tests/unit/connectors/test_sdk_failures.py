# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the SDK's shared failure classification and health summary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
import pytest
from kestrel.connectors.sdk.failures import (
    FailureMessages,
    classify_http_failure,
    format_probe_failures,
    http_status,
    is_network_error,
    is_skippable_gate,
    is_status_429,
    response_headers,
    summarize_probe_failures,
)


def _http_error(status: int, headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.example.com/things")
    response = httpx.Response(status, headers=headers or {}, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class _StubResponse:
    def __init__(self, status_code: int, headers: Any = None) -> None:
        self.status_code = status_code
        self.headers = headers


class _StubError(Exception):
    def __init__(self, response: Any = None) -> None:
        super().__init__("stub")
        self.response = response


def _named_error(name: str) -> Exception:
    return type(name, (Exception,), {})()


# -- http_status / response_headers ---------------------------------------


def test_http_status_reads_the_attached_response() -> None:
    assert http_status(_http_error(418)) == 418
    assert http_status(_StubError(_StubResponse(503))) == 503


def test_http_status_is_none_without_a_response() -> None:
    assert http_status(ValueError("no response")) is None
    assert http_status(_StubError(None)) is None


def test_response_headers_lower_cases_names() -> None:
    exc = _http_error(403, {"X-RateLimit-Remaining": "0"})
    assert response_headers(exc)["x-ratelimit-remaining"] == "0"


@pytest.mark.parametrize("headers", [None, "not-a-mapping", 42])
def test_response_headers_is_empty_for_missing_or_odd_headers(headers: Any) -> None:
    assert response_headers(_StubError(_StubResponse(403, headers))) == {}
    assert response_headers(ValueError("x")) == {}


# -- is_network_error -----------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
        httpx.RemoteProtocolError("bad frame"),
        _named_error("ProxyError"),
        _named_error("NetworkError"),
        _named_error("SocketTimeout"),
        _named_error("CouldNotConnect"),
    ],
)
def test_transport_failures_are_network_errors(exc: BaseException) -> None:
    assert is_network_error(exc) is True


@pytest.mark.parametrize("exc", [ValueError("x"), RuntimeError("x"), _named_error("FixtureNotFound")])
def test_other_exceptions_are_not_network_errors(exc: BaseException) -> None:
    assert is_network_error(exc) is False


# -- is_skippable_gate ----------------------------------------------------


@pytest.mark.parametrize("status", [403, 404])
def test_permission_and_missing_resources_are_skippable(status: int) -> None:
    assert is_skippable_gate(_http_error(status)) is True


@pytest.mark.parametrize("status", [401, 429, 500])
def test_other_statuses_are_not_skippable(status: int) -> None:
    assert is_skippable_gate(_http_error(status)) is False


def test_a_rate_limit_is_never_skippable_even_with_a_gate_status() -> None:
    exc = _http_error(403, {"x-ratelimit-remaining": "0"})

    def throttled(e: BaseException) -> bool:
        return response_headers(e).get("x-ratelimit-remaining") == "0"

    assert is_skippable_gate(exc) is True
    assert is_skippable_gate(exc, is_rate_limit=throttled) is False


def test_skippable_statuses_are_configurable() -> None:
    assert is_skippable_gate(_http_error(404), statuses={403}) is False
    assert is_skippable_gate(_http_error(410), statuses={403, 410}) is True


def test_default_rate_limit_predicate_is_429() -> None:
    assert is_status_429(_http_error(429)) is True
    assert is_status_429(_http_error(403)) is False
    assert is_status_429(ValueError("x")) is False


# -- classify_http_failure ------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "authentication"),
        (403, "permission"),
        (429, "rate_limit"),
        (404, "http_404"),
        (500, "http_500"),
    ],
)
def test_classify_by_status(status: int, expected: str) -> None:
    assert classify_http_failure(_http_error(status)) == expected


def test_classify_network_and_unknown() -> None:
    assert classify_http_failure(httpx.ConnectTimeout("slow")) == "network"
    assert classify_http_failure(ValueError("???")) == "unknown"


def test_classify_consults_the_rate_limit_predicate_first() -> None:
    exc = _http_error(403, {"retry-after": "5"})
    assert classify_http_failure(exc) == "permission"
    assert classify_http_failure(exc, is_rate_limit=lambda e: "retry-after" in response_headers(e)) == "rate_limit"


def test_a_custom_predicate_replaces_the_429_default() -> None:
    assert classify_http_failure(_http_error(429), is_rate_limit=lambda e: False) == "http_429"


# -- summarize_probe_failures ---------------------------------------------


_MESSAGES = FailureMessages(
    authentication="auth: {probes}",
    permission="perm: {probes}",
    rate_limit="slow: {probes}",
    network="net: {probes}",
    fallback="other: {probes}",
)


def test_format_probe_failures_sorts_by_label() -> None:
    assert format_probe_failures({"b": "network", "a": "permission"}) == "a (permission), b (network)"


@pytest.mark.parametrize(
    ("failures", "expected"),
    [
        ({"a": "permission", "b": "authentication"}, "auth: a (permission), b (authentication)"),
        ({"a": "rate_limit", "b": "permission"}, "perm: a (rate_limit), b (permission)"),
        ({"a": "network", "b": "rate_limit"}, "slow: a (network), b (rate_limit)"),
        ({"a": "network", "b": "network"}, "net: a (network), b (network)"),
        ({"a": "network", "b": "http_500"}, "other: a (network), b (http_500)"),
        ({"a": "unknown"}, "other: a (unknown)"),
        ({}, "other: "),
    ],
)
def test_summary_precedence(failures: dict[str, str], expected: str) -> None:
    assert summarize_probe_failures(failures, _MESSAGES) == expected


def test_template_substitution_leaves_other_braces_alone() -> None:
    messages = FailureMessages(
        authentication="GET /orgs/{org} failed for {probes}",
        permission="",
        rate_limit="",
        network="",
        fallback="",
    )
    assert summarize_probe_failures({"x": "authentication"}, messages) == "GET /orgs/{org} failed for x (authentication)"


def test_callable_messages_receive_probes_and_failures() -> None:
    seen: list[tuple[str, Mapping[str, str]]] = []

    def permission(probes: str, failures: Mapping[str, str]) -> str:
        seen.append((probes, failures))
        return f"missing {len(failures)}"

    messages = FailureMessages(
        authentication="",
        permission=permission,
        rate_limit="",
        network="",
        fallback="",
    )
    failures = {"repos.list": "permission"}
    assert summarize_probe_failures(failures, messages) == "missing 1"
    assert seen == [("repos.list (permission)", failures)]
