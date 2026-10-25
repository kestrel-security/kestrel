# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""HTTP status helpers for classified skip (403/404) vs fail-the-sync.

Okta is simpler than GitHub here -- rate limits are plain 429s, not
status-403-with-a-header -- but the rule that matters is the same: a throttled
request is **not** a permission gate. Dropping an object family because the
token was rate-limited reports an incomplete inventory as a complete one, and
`detect_deletions` then reads the missing rows as removal, filling `/changes`
with revocations that never happened.
"""

from __future__ import annotations

from kestrel.connectors.sdk.failures import classify_http_failure, http_status, is_skippable_gate

__all__ = ["classify_okta_failure", "is_rate_limit", "is_skippable"]


def is_rate_limit(exc: BaseException) -> bool:
    """Okta throttles with a plain 429 and nothing else."""
    return http_status(exc) == 429


def is_skippable(exc: BaseException) -> bool:
    """Permission or plan gates: collect the rest of the sync.

    A rate-limited request is explicitly not skippable -- see the module
    docstring. It fails the run so the operator retries against a complete
    inventory.
    """
    return is_skippable_gate(exc, is_rate_limit=is_rate_limit)


def classify_okta_failure(exc: BaseException) -> str:
    """Map transport/httpx failures to a coarse operator-facing failure class."""
    return classify_http_failure(exc, is_rate_limit=is_rate_limit)
