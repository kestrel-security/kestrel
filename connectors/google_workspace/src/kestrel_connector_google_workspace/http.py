# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""HTTP helpers: classified skip vs fail-the-sync, and pagination caps.

Directory / Drive / admin-role lists must never silently truncate. Reports
may skip on permission/plan gates so the rest of the sync
still completes.
"""

from __future__ import annotations

from kestrel.connectors.sdk.failures import GOOGLE_QUOTA_REASONS, http_status, is_skippable_gate, response_quota_reasons

__all__ = ["PaginationLimitError", "is_rate_limit", "is_skippable"]


def is_skippable(exc: BaseException) -> bool:
    """A permission or plan gate on an optional family: record it, keep going.

    A throttled 403 is not skippable -- dropping a family because the token
    was rate-limited would report an incomplete inventory as complete.
    """
    return is_skippable_gate(exc, is_rate_limit=is_rate_limit)


def is_rate_limit(exc: BaseException) -> bool:
    """A 429, or a 403 whose *body* names one of Google's quota reasons.

    Google carries no rate-limit headers, and ``httpx.HTTPStatusError``'s
    message is ``Client error '403 Forbidden' for url ...`` -- the body never
    reaches ``str(exc)``. Matching the message alone classified every quota
    403 as a permission error, skipped the family, and told the operator to
    grant a scope they already had. The message check stays for wrapped errors
    that quote the body.
    """
    status = http_status(exc)
    if status == 429:
        return True
    if status != 403:
        return False
    if response_quota_reasons(exc) & GOOGLE_QUOTA_REASONS:
        return True
    msg = str(exc).casefold()
    return "ratelimitexceeded" in msg or "rate limit" in msg


class PaginationLimitError(RuntimeError):
    """Raised when Google still returns nextPageToken after the page cap.

    Callers must not treat a partial list as complete.
    """
