# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Client-IP resolution behind trusted proxies and rate-limit bucket keys.

Regressions for two findings:

* every browser login reached the API from the web server's address, so one
  noisy client filled the single shared login bucket for everybody; and
* any random ``Authorization: Bearer`` value got its own bucket before
  authentication, so rotating tokens bypassed throttling entirely.

The middleware is exercised on a bare Starlette app (no database).
"""

from __future__ import annotations

import ipaddress

import pytest
from fastapi.testclient import TestClient
from kestrel.rate_limit import store as rate_limit_store
from kestrel.rate_limit.classify import RateLimitTier
from kestrel.rate_limit.config import RateLimitSettings
from kestrel.rate_limit.store import MemoryRateLimitStore
from kestrel_api.client_ip import resolve_client_ip
from kestrel_api.middleware import rate_limit as rl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

TRUSTED = (ipaddress.ip_network("172.16.0.0/12"),)


# -- resolve_client_ip ---------------------------------------------------------


def test_untrusted_peer_ignores_forwarded_for():
    assert resolve_client_ip("203.0.113.9", "198.51.100.1", TRUSTED) == "203.0.113.9"


def test_no_trusted_proxies_configured_ignores_forwarded_for():
    assert resolve_client_ip("172.18.0.3", "198.51.100.1", ()) == "172.18.0.3"


def test_trusted_peer_uses_the_rightmost_untrusted_hop():
    # A client-injected "1.2.3.4" sits left of the address the proxy saw.
    assert resolve_client_ip("172.18.0.3", "1.2.3.4, 198.51.100.7", TRUSTED) == "198.51.100.7"


def test_trusted_hops_in_the_chain_are_skipped():
    assert resolve_client_ip("172.18.0.3", "198.51.100.7, 172.18.0.9", TRUSTED) == "198.51.100.7"


def test_garbage_in_the_chain_stops_the_walk():
    assert resolve_client_ip("172.18.0.3", "not-an-ip, 172.18.0.9", TRUSTED) == "172.18.0.9"


def test_ports_and_mapped_addresses_are_normalised():
    assert resolve_client_ip("172.18.0.3", "198.51.100.7:51234", TRUSTED) == "198.51.100.7"
    assert resolve_client_ip("::ffff:172.18.0.3", "[2001:db8::5]:443", TRUSTED) == "2001:db8::5"


def test_trusted_peer_without_header_is_the_client():
    assert resolve_client_ip("172.18.0.3", None, TRUSTED) == "172.18.0.3"


# -- MemoryRateLimitStore eviction ---------------------------------------------


def test_memory_store_evicts_expired_windows(monkeypatch):
    now = [1_000.0]
    monkeypatch.setattr(rate_limit_store.time, "monotonic", lambda: now[0])
    store = MemoryRateLimitStore()
    for i in range(50):
        store.increment(f"ip:{i}", window_seconds=60)
    assert len(store) == 50

    now[0] += 61 + MemoryRateLimitStore.SWEEP_INTERVAL_SECONDS
    store.increment("ip:new", window_seconds=60)

    assert len(store) == 1


# -- bucket keys -----------------------------------------------------------------


def _request(headers: dict[str, str], peer: str = "203.0.113.9") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/findings",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 1234),
    }
    return Request(scope)


@pytest.fixture
def fresh_token_cache(monkeypatch):
    cache = rl.ValidatedTokenCache()
    monkeypatch.setattr(rl, "validated_tokens", cache)
    return cache


def test_unvalidated_bearer_tokens_share_the_ip_bucket(fresh_token_cache):
    a = rl.identity_key(_request({"Authorization": "Bearer random-1"}), tier=RateLimitTier.DEFAULT)
    b = rl.identity_key(_request({"Authorization": "Bearer random-2"}), tier=RateLimitTier.DEFAULT)
    assert a == b == "ip:203.0.113.9"


def test_a_validated_token_gets_its_own_bucket(fresh_token_cache):
    rl.remember_validated_token("real-token")
    key = rl.identity_key(_request({"Authorization": "Bearer real-token"}), tier=RateLimitTier.EXPENSIVE)
    assert key.startswith("tok:")


def test_login_always_keys_on_ip(fresh_token_cache):
    rl.remember_validated_token("real-token")
    key = rl.identity_key(_request({"Authorization": "Bearer real-token"}), tier=RateLimitTier.LOGIN)
    assert key == "ip:203.0.113.9"


def test_validated_token_cache_expires_and_is_bounded(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: now[0])
    cache = rl.ValidatedTokenCache(ttl_seconds=10, max_entries=2)
    cache.remember("a")
    cache.remember("b")
    cache.remember("c")
    assert not cache.contains("a")  # evicted: over max_entries
    assert cache.contains("c")
    now[0] = 11
    assert not cache.contains("c")


def test_login_email_bucket_normalises_the_address():
    runtime = rl.RateLimitRuntime(
        settings=RateLimitSettings(enabled=True, login_limit=2, backend="memory"),
        store=MemoryRateLimitStore(),
    )
    first = rl.check_login_email_limit("Victim@Example.com", rt=runtime)
    second = rl.check_login_email_limit("  victim@example.com ", rt=runtime)
    third = rl.check_login_email_limit("VICTIM@example.COM", rt=runtime)
    assert first is not None
    assert first.allowed
    assert second is not None
    assert second.allowed
    assert third is not None
    assert not third.allowed
    other = rl.check_login_email_limit("someone-else@example.com", rt=runtime)
    assert other is not None
    assert other.allowed


def test_login_email_bucket_is_off_when_rate_limiting_is_disabled():
    runtime = rl.RateLimitRuntime(settings=RateLimitSettings(enabled=False), store=MemoryRateLimitStore())
    assert rl.check_login_email_limit("a@example.com", rt=runtime) is None


# -- middleware end to end ----------------------------------------------------------


def _app(runtime: rl.RateLimitRuntime) -> Starlette:
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[
            Route("/api/v1/auth/login", ok, methods=["POST"]),
            Route("/api/v1/policies/validate", ok, methods=["POST"]),
        ]
    )
    app.add_middleware(rl.RateLimitMiddleware, runtime_override=runtime)
    return app


@pytest.fixture
def limited_runtime(monkeypatch, fresh_token_cache):
    monkeypatch.setenv("KESTREL_TRUSTED_PROXIES", "172.16.0.0/12")
    return rl.RateLimitRuntime(
        settings=RateLimitSettings(enabled=True, login_limit=2, expensive_limit=2, backend="memory"),
        store=MemoryRateLimitStore(),
    )


def test_login_buckets_are_per_forwarded_client(limited_runtime):
    client = TestClient(_app(limited_runtime), client=("172.18.0.3", 5000))

    def login(ip: str) -> int:
        return client.post("/api/v1/auth/login", headers={"X-Forwarded-For": ip}).status_code

    assert [login("198.51.100.1") for _ in range(3)] == [200, 200, 429]
    # A different browser behind the same web server is unaffected.
    assert login("198.51.100.2") == 200


def test_rotating_random_tokens_does_not_escape_the_limit(limited_runtime):
    client = TestClient(_app(limited_runtime), client=("203.0.113.50", 5000))

    codes = [
        client.post("/api/v1/policies/validate", headers={"Authorization": f"Bearer random-{i}"}).status_code
        for i in range(4)
    ]

    assert codes == [200, 200, 429, 429]


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/findings/00000000-0000-0000-0000-000000000001/verify",
        "/api/v1/policies/generate",
        "/api/v1/connector-instances/00000000-0000-0000-0000-000000000001/sync",
    ],
)
def test_sync_and_generation_routes_are_in_the_expensive_tier(path):
    from kestrel.rate_limit.classify import classify_request

    assert classify_request("POST", path) == RateLimitTier.EXPENSIVE
    assert classify_request("GET", path) == RateLimitTier.DEFAULT
