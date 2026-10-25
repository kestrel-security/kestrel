# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the shared LiveHTTPTransport.

Every live connector paginates and retries through this class, and until now
none of it was covered: Link-header walking, the page cap, cross-origin
refusal, and the rate-limit ladder were all unverified. The `transport=` and
`sleep=` constructor seams exist precisely so this can be exercised against
canned responses with no network and no real sleeping.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from kestrel.connectors.sdk.transport import LiveHTTPTransport

BASE_URL = "https://api.github.com"


def _transport(handler: Any) -> tuple[LiveHTTPTransport, list[float]]:
    slept: list[float] = []
    live = LiveHTTPTransport(
        base_url=BASE_URL,
        headers={"Authorization": "Bearer token"},
        transport=httpx.MockTransport(handler),
        sleep=slept.append,
    )
    return live, slept


def _json_response(payload: Any, *, status: int = 200, headers: dict[str, str] | None = None):
    return httpx.Response(status, content=json.dumps(payload), headers=headers or {})


def test_request_returns_decoded_json() -> None:
    live, _ = _transport(lambda request: _json_response({"login": "acme"}))
    assert live.request("GET", "/orgs/acme") == {"login": "acme"}


def test_paginate_follows_link_headers_until_exhausted() -> None:
    pages = {
        "/items": ([{"id": 1}], {"Link": f'<{BASE_URL}/items?page=2>; rel="next"'}),
        "/items?page=2": ([{"id": 2}], {"Link": f'<{BASE_URL}/items?page=3>; rel="next"'}),
        "/items?page=3": ([{"id": 3}], {}),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.raw_path.decode()
        payload, headers = pages[key]
        return _json_response(payload, headers=headers)

    live, _ = _transport(handler)
    assert [row["id"] for row in live.paginate("GET", "/items")] == [1, 2, 3]


def test_paginate_wraps_a_non_list_page_as_a_single_row() -> None:
    live, _ = _transport(lambda request: _json_response({"id": 1}))
    assert list(live.paginate("GET", "/thing")) == [{"id": 1}]


def test_paginate_refuses_a_cross_origin_next_link() -> None:
    live, _ = _transport(
        lambda request: _json_response([{"id": 1}], headers={"Link": '<https://evil.example/items>; rel="next"'})
    )
    with pytest.raises(RuntimeError, match="Refusing pagination next URL host"):
        list(live.paginate("GET", "/items"))


def test_paginate_stops_at_the_page_cap_rather_than_looping_forever() -> None:
    # A provider that always advertises a next page would otherwise spin until
    # the worker is killed.
    live, _ = _transport(
        lambda request: _json_response([{"id": 1}], headers={"Link": f'<{BASE_URL}/items?page=2>; rel="next"'})
    )
    with pytest.raises(RuntimeError, match="exceeded 10000 pages"):
        list(live.paginate("GET", "/items"))


def test_429_with_retry_after_sleeps_that_long_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _json_response({}, status=429, headers={"Retry-After": "7"})
        return _json_response({"ok": True})

    live, slept = _transport(handler)
    assert live.request("GET", "/thing") == {"ok": True}
    assert slept == [7.0]


def test_429_without_hints_falls_back_to_exponential_backoff() -> None:
    live, slept = _transport(lambda request: _json_response({}, status=429))
    with pytest.raises(httpx.HTTPStatusError):
        live.request("GET", "/thing")
    assert slept == [2.0, 4.0, 8.0]


def test_github_primary_rate_limit_403_is_retried_not_treated_as_permission() -> None:
    # GitHub signals its primary rate limit with 403 + x-ratelimit-remaining: 0.
    # Without this branch a throttled sync looks like a lost token.
    import time

    calls = {"n": 0}
    reset_at = str(int(time.time()) + 5)

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _json_response(
                {},
                status=403,
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset_at},
            )
        return _json_response({"ok": True})

    live, slept = _transport(handler)
    assert live.request("GET", "/thing") == {"ok": True}
    assert len(slept) == 1
    assert 0 < slept[0] <= 7.0


def test_plain_403_is_not_retried_so_permission_errors_surface_immediately() -> None:
    live, slept = _transport(lambda request: _json_response({}, status=403))
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        live.request("GET", "/orgs/acme/audit-log")
    assert excinfo.value.response.status_code == 403
    assert slept == []


def test_a_rate_limit_reset_beyond_the_wait_cap_fails_instead_of_blocking() -> None:
    # Primary limits can reset an hour out. Sleeping through that would pin a
    # worker and look like a hang, so the run fails and retries on its own.
    import time

    reset_at = str(int(time.time()) + 3600)
    live, slept = _transport(
        lambda request: _json_response(
            {},
            status=403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset_at},
        )
    )
    with pytest.raises(httpx.HTTPStatusError):
        live.request("GET", "/thing")
    assert slept == []


def test_a_healthy_response_carrying_ratelimit_headers_is_not_throttled() -> None:
    live, slept = _transport(
        lambda request: _json_response(
            {"ok": True},
            headers={"x-ratelimit-remaining": "4999", "x-ratelimit-reset": "9999999999"},
        )
    )
    assert live.request("GET", "/thing") == {"ok": True}
    assert slept == []


# -- Empty bodies -------------------------------------------------------------


def test_a_204_no_content_is_a_success_with_no_body_not_a_decode_error() -> None:
    # GitHub answers the vulnerability-alerts probe with 204 when alerts are
    # enabled. Decoding that as JSON raised an error no classifier could read.
    live, _ = _transport(lambda request: httpx.Response(204))
    assert live.request("GET", "/repos/acme/web-app/vulnerability-alerts") is None


def test_an_empty_200_body_is_none_rather_than_a_decode_error() -> None:
    live, _ = _transport(lambda request: httpx.Response(200, content=b""))
    assert live.request("GET", "/thing") is None


def test_request_raw_exposes_status_headers_and_bytes() -> None:
    live, _ = _transport(lambda request: httpx.Response(200, content=b"\x1f\x8bnot-json", headers={"Retry-After": "3"}))
    raw = live.request_raw("GET", "/admin.analytics.getFile?type=member")
    assert raw.status_code == 200
    assert raw.headers["retry-after"] == "3"
    assert raw.content == b"\x1f\x8bnot-json"


# -- Transient server failures ------------------------------------------------


def test_a_502_on_a_get_is_retried_with_backoff_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(502, content=b"bad gateway")
        return _json_response({"ok": True})

    live, slept = _transport(handler)
    assert live.request("GET", "/thing") == {"ok": True}
    assert calls["n"] == 3
    assert slept == [1.0, 2.0]


def test_server_errors_give_up_after_three_attempts() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    live, slept = _transport(handler)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        live.request("GET", "/thing")
    assert excinfo.value.response.status_code == 503
    assert calls["n"] == 3
    assert slept == [1.0, 2.0]


def test_a_transport_error_on_a_get_is_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadTimeout("slow provider", request=request)
        return _json_response([{"id": 1}])

    live, slept = _transport(handler)
    assert list(live.paginate("GET", "/items")) == [{"id": 1}]
    assert slept == [1.0]


def test_a_transport_error_that_persists_is_raised_after_the_ladder() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    live, slept = _transport(handler)
    with pytest.raises(httpx.ConnectError):
        live.request("GET", "/thing")
    assert slept == [1.0, 2.0]


def test_a_post_is_not_retried_unless_the_connector_declares_it_idempotent() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500)

    live, slept = _transport(handler)
    with pytest.raises(httpx.HTTPStatusError):
        live.request("POST", "/graphql", json={"query": "{}"})
    assert calls["n"] == 1
    assert slept == []


def test_a_declared_read_only_post_is_retried_like_a_get() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(504)
        return _json_response({"data": {}})

    slept: list[float] = []
    live = LiveHTTPTransport(
        base_url=BASE_URL,
        headers={},
        transport=httpx.MockTransport(handler),
        sleep=slept.append,
        idempotent_methods=("GET", "HEAD", "POST"),
    )
    assert live.request("POST", "/graphql", json={"query": "{}"}) == {"data": {}}
    assert slept == [1.0]


def test_a_4xx_is_never_retried_as_a_server_error() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(422)

    live, slept = _transport(handler)
    with pytest.raises(httpx.HTTPStatusError):
        live.request("GET", "/thing")
    assert calls["n"] == 1
    assert slept == []


# -- Google's body-only quota signal ------------------------------------------


def _google_quota_403() -> httpx.Response:
    return _json_response(
        {
            "error": {
                "code": 403,
                "message": "Rate Limit Exceeded",
                "errors": [{"domain": "usageLimits", "reason": "rateLimitExceeded", "message": "Rate Limit Exceeded"}],
            }
        },
        status=403,
    )


def test_a_403_whose_body_names_a_quota_reason_is_backed_off_and_retried() -> None:
    # Google carries no rate-limit headers: without reading the body this was
    # a permission error, reported as a missing scope the operator already had.
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _google_quota_403()
        return _json_response({"users": []})

    live, slept = _transport(handler)
    assert live.request("GET", "/admin/directory/v1/users") == {"users": []}
    assert slept == [2.0]


def test_a_persistent_quota_403_still_fails_after_the_retry_ladder() -> None:
    live, slept = _transport(lambda request: _google_quota_403())
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        live.request("GET", "/admin/directory/v1/users")
    assert excinfo.value.response.status_code == 403
    assert slept == [2.0, 4.0, 8.0]


def test_a_403_with_a_non_quota_body_is_still_a_permission_error() -> None:
    live, slept = _transport(
        lambda request: _json_response(
            {"error": {"code": 403, "errors": [{"reason": "insufficientPermissions"}]}}, status=403
        )
    )
    with pytest.raises(httpx.HTTPStatusError):
        live.request("GET", "/admin/directory/v1/users")
    assert slept == []
