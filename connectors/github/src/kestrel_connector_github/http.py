# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""HTTP status helpers for classified skip vs fail-the-sync.

GitHub differs from most providers in two ways that matter here:

1. **Primary rate limits return 403, not 429.** A 403 carrying
   ``x-ratelimit-remaining: 0`` is a rate limit; a 403 without it is a genuine
   permission or plan gate. Treating all 403s alike would either retry
   permission errors forever or fail syncs on transient throttling.
2. **Whole object families are plan-gated.** The audit log API is GitHub
   Enterprise Cloud only, so a Team-plan org returns 403 for
   ``/orgs/{org}/audit-log`` while every other endpoint works. That must
   degrade the run, not fail it.
"""

from __future__ import annotations

from kestrel.connectors.sdk.failures import (
    classify_http_failure,
    http_status,
    is_skippable_gate,
    response_headers,
)

__all__ = ["classify_github_failure", "http_status", "is_graphql_gate", "is_rate_limit", "is_skippable"]


def is_rate_limit(exc: BaseException) -> bool:
    """True for both GitHub rate-limit shapes.

    Primary limits surface as 403 with ``x-ratelimit-remaining: 0``; secondary
    (abuse) limits surface as 403 or 429 with ``retry-after``.
    """
    status = http_status(exc)
    if status == 429:
        return True
    if status != 403:
        return False
    headers = response_headers(exc)
    if headers.get("x-ratelimit-remaining") == "0":
        return True
    return "retry-after" in headers


_GRAPHQL_GATE_TYPES = frozenset({"FORBIDDEN", "INSUFFICIENT_SCOPES", "NOT_FOUND"})


def is_graphql_gate(exc: BaseException) -> bool:
    """A GraphQL ``errors`` entry that means "you may not read this", which
    GitHub returns with HTTP 200 rather than a 403."""
    error_type = getattr(exc, "error_type", None)
    return isinstance(error_type, str) and error_type.upper() in _GRAPHQL_GATE_TYPES


def is_skippable(exc: BaseException) -> bool:
    """Permission or plan gates: collect the rest of the sync.

    A rate-limited 403 is explicitly *not* skippable — silently dropping an
    object type because the token was throttled would report an incomplete
    inventory as a complete one, which change detection would then read as
    mass deletion.
    """
    if is_graphql_gate(exc) and not is_rate_limit(exc):
        return True
    return is_skippable_gate(exc, is_rate_limit=is_rate_limit)


def classify_github_failure(exc: BaseException) -> str:
    """Map transport/httpx failures to a coarse operator-facing failure class."""
    if is_graphql_gate(exc) and not is_rate_limit(exc):
        return "permission"
    return classify_http_failure(exc, is_rate_limit=is_rate_limit)
