# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Map HTTP method + path to a rate-limit tier."""

from __future__ import annotations

from enum import StrEnum


class RateLimitTier(StrEnum):
    EXEMPT = "exempt"
    LOGIN = "login"
    EXPENSIVE = "expensive"
    DEFAULT = "default"


# Paths that must never be throttled (probes / scrapers).
_EXEMPT_PREFIXES = (
    "/healthz",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
)


def classify_request(method: str, path: str) -> RateLimitTier:
    """Return the tier for this request.

    Expensive matching is intentional substring/prefix based so path params
    (connector/policy UUIDs) still hit the tighter bucket.
    """
    normalized = path.split("?", 1)[0]
    method_u = method.upper()

    for prefix in _EXEMPT_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return RateLimitTier.EXEMPT

    if method_u == "POST" and normalized.rstrip("/") == "/api/v1/auth/login":
        return RateLimitTier.LOGIN

    if not normalized.startswith("/api/v1"):
        return RateLimitTier.EXEMPT

    if method_u == "POST" and _is_expensive(normalized):
        return RateLimitTier.EXPENSIVE

    return RateLimitTier.DEFAULT


def _is_expensive(path: str) -> bool:
    if path.rstrip("/") == "/api/v1/policies/validate":
        return True
    if path.rstrip("/") == "/api/v1/policies/test-draft":
        return True
    if path.rstrip("/") == "/api/v1/policies/dry-run-draft":
        return True
    if path.rstrip("/") == "/api/v1/policies/fixtures/from-matches":
        return True
    # POST /api/v1/policies/generate -- policy synthesis from an intent
    if path.rstrip("/") == "/api/v1/policies/generate":
        return True
    # POST /api/v1/findings/{id}/verify -- a policy dry-run, optionally a sync
    if path.startswith("/api/v1/findings/") and path.rstrip("/").endswith("/verify"):
        return True
    # POST /api/v1/policies/{id}/test, /dry-run, /evaluate, or fixtures/from-matches
    if path.startswith("/api/v1/policies/") and path.rstrip("/").endswith(
        ("/test", "/dry-run", "/evaluate", "/fixtures/from-matches")
    ):
        return True
    # POST /api/v1/connectors/probe -- a live call to a provider
    if path.rstrip("/") == "/api/v1/connectors/probe":
        return True
    # POST /api/v1/settings/email/test -- a live SMTP connection
    if path.rstrip("/") == "/api/v1/settings/email/test":
        return True
    # POST /api/v1/connector-instances/{id}/sync
    return path.startswith("/api/v1/connector-instances/") and path.rstrip("/").endswith("/sync")
