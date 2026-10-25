# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Fixed-window API rate limiting.

Core store + classifier live here so unit tests need no Redis/FastAPI.
The API wires a Redis (or memory) backend via ``kestrel_api.middleware.rate_limit``.
"""

from kestrel.rate_limit.classify import RateLimitTier, classify_request
from kestrel.rate_limit.config import RateLimitSettings, load_rate_limit_settings
from kestrel.rate_limit.store import (
    FixedWindowResult,
    MemoryRateLimitStore,
    RateLimitStore,
    check_fixed_window,
)

__all__ = [
    "FixedWindowResult",
    "MemoryRateLimitStore",
    "RateLimitSettings",
    "RateLimitStore",
    "RateLimitTier",
    "check_fixed_window",
    "classify_request",
    "load_rate_limit_settings",
]
