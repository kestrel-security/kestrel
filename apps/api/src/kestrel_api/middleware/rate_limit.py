# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Redis fixed-window rate-limit backend + ASGI middleware."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from kestrel.auth.tokens import hash_token
from kestrel.rate_limit.classify import RateLimitTier, classify_request
from kestrel.rate_limit.config import RateLimitSettings, load_rate_limit_settings
from kestrel.rate_limit.store import (
    FixedWindowResult,
    MemoryRateLimitStore,
    RateLimitStore,
    check_fixed_window,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from kestrel_api.client_ip import client_ip

logger = logging.getLogger("kestrel_api.rate_limit")


class RedisRateLimitStore:
    """Redis INCR + EXPIRE fixed window. Failures raise; middleware fail-opens."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = pipe.execute()
        count = int(count)
        ttl = int(ttl)
        if count == 1 or ttl < 0:
            self._redis.expire(key, window_seconds)
            ttl = window_seconds
        return count, max(1, ttl)


def build_rate_limit_store(settings: RateLimitSettings | None = None) -> RateLimitStore:
    """Prefer Redis when configured; fall back to process memory with a warning."""
    settings = settings or load_rate_limit_settings()
    want_redis = settings.backend == "redis" or (settings.backend == "auto" and bool(settings.redis_url))
    if want_redis and settings.redis_url:
        try:
            import redis

            client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
            client.ping()
            logger.info("rate_limit_backend=redis")
            return RedisRateLimitStore(client)
        except Exception as exc:  # noqa: BLE001 — intentional fail-open to memory
            if settings.backend == "redis":
                logger.error(
                    "Redis rate-limit backend required but unavailable (%s); using memory",
                    exc,
                )
            else:
                logger.warning(
                    "Redis rate-limit unavailable (%s); using in-process memory store",
                    exc,
                )
    else:
        logger.info("rate_limit_backend=memory")
    return MemoryRateLimitStore()


@dataclass
class RateLimitRuntime:
    """Mutable holder so tests can swap settings/store without rebuilding ASGI."""

    settings: RateLimitSettings = field(default_factory=load_rate_limit_settings)
    store: RateLimitStore = field(default_factory=build_rate_limit_store)

    def configure(
        self,
        *,
        settings: RateLimitSettings | None = None,
        store: RateLimitStore | None = None,
    ) -> None:
        if settings is not None:
            self.settings = settings
        if store is not None:
            self.store = store
        if settings is not None and store is None:
            self.store = build_rate_limit_store(settings)


# Process-wide runtime used by the middleware instance registered in main.py.
runtime = RateLimitRuntime()


class ValidatedTokenCache:
    """Hashes of bearer tokens that recently authenticated successfully.

    The middleware runs before authentication, so it cannot tell a real
    token from a random string. Giving every distinct ``Authorization`` value
    its own bucket let a caller rotate random tokens and never be throttled.
    Instead a token gets its own bucket only once `get_current_operator` has
    accepted it (and for ``ttl_seconds`` after); anything else is bucketed by
    client IP. Process-local and bounded: a worker that has not yet seen a
    token simply counts its first request against the IP.
    """

    def __init__(self, *, ttl_seconds: float = 300.0, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, float] = OrderedDict()

    def remember(self, token_hash: str) -> None:
        expires = time.monotonic() + self._ttl
        with self._lock:
            self._entries[token_hash] = expires
            self._entries.move_to_end(token_hash)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def contains(self, token_hash: str) -> bool:
        now = time.monotonic()
        with self._lock:
            expires = self._entries.get(token_hash)
            if expires is None:
                return False
            if expires <= now:
                del self._entries[token_hash]
                return False
            return True

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


validated_tokens = ValidatedTokenCache()


def remember_validated_token(raw_token: str) -> None:
    """Called by the auth dependency once a bearer token has been accepted."""
    validated_tokens.remember(hash_token(raw_token))


def identity_key(request: Request, *, tier: RateLimitTier) -> str:
    """Bucket key: a validated credential's hash, else the client IP.

    Login always keys on IP (plus a per-email bucket in the login route, see
    `check_login_email_limit`). Other tiers use the bearer token's hash only
    when that token has already authenticated (`ValidatedTokenCache`), so a
    caller cannot mint fresh buckets with random tokens; unknown or invalid
    tokens share their client IP's bucket. The client IP honours
    ``X-Forwarded-For`` only from ``KESTREL_TRUSTED_PROXIES``.
    """
    ip_key = f"ip:{client_ip(request)}"
    if tier == RateLimitTier.LOGIN:
        return ip_key

    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
        if raw:
            token_hash = hash_token(raw)
            if validated_tokens.contains(token_hash):
                return f"tok:{token_hash}"
    return ip_key


def normalize_login_email(email: str) -> str:
    return email.strip().casefold()


def check_login_email_limit(email: str, *, rt: RateLimitRuntime | None = None) -> FixedWindowResult | None:
    """Record a login attempt against the per-email bucket.

    Complements the per-IP bucket: an attacker spreading guesses for one
    account across many addresses is still limited, and one noisy address
    no longer blocks everyone else's sign-in. The key holds a hash, not the
    address. Returns None when limiting is off or the store fails (fail-open,
    as the middleware does).
    """
    active = rt or runtime
    settings = active.settings
    if not settings.enabled:
        return None
    digest = hashlib.sha256(normalize_login_email(email).encode()).hexdigest()
    try:
        return check_fixed_window(
            active.store,
            key=f"rl:login:email:{digest}",
            limit=settings.login_limit,
            window_seconds=settings.window_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — fail-open on store errors
        logger.warning("rate_limit_check_failed path=login-email err=%s", exc)
        return None


def rate_limit_headers(result: FixedWindowResult) -> dict[str, str]:
    headers = {
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset": str(int(result.reset_at)),
    }
    if not result.allowed:
        headers["Retry-After"] = str(result.retry_after_seconds)
    return headers


def _apply_headers(response: Response, result: FixedWindowResult) -> None:
    for name, value in rate_limit_headers(result).items():
        response.headers[name] = value


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Throttle /api/v1 with fixed windows; emit 429 + Retry-After when exceeded."""

    def __init__(self, app, *, runtime_override: RateLimitRuntime | None = None) -> None:
        super().__init__(app)
        self._runtime = runtime_override or runtime

    async def dispatch(self, request: Request, call_next):
        settings = self._runtime.settings
        if not settings.enabled:
            return await call_next(request)

        tier = classify_request(request.method, request.url.path)
        if tier == RateLimitTier.EXEMPT:
            return await call_next(request)

        limit = settings.limit_for(tier.value)
        key = f"rl:{tier.value}:{identity_key(request, tier=tier)}"

        try:
            result = check_fixed_window(
                self._runtime.store,
                key=key,
                limit=limit,
                window_seconds=settings.window_seconds,
            )
        except Exception as exc:  # noqa: BLE001 — fail-open on store errors
            logger.warning("rate_limit_check_failed path=%s err=%s", request.url.path, exc)
            return await call_next(request)

        if not result.allowed:
            logger.info(
                "rate_limit_exceeded tier=%s path=%s limit=%s count=%s",
                tier.value,
                request.url.path,
                result.limit,
                result.count,
            )
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Retry later.",
                    "tier": tier.value,
                    "limit": result.limit,
                    "retry_after_seconds": result.retry_after_seconds,
                },
            )
            _apply_headers(response, result)
            return response

        response = await call_next(request)
        _apply_headers(response, result)
        return response
