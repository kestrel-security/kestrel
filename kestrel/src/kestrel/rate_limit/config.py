# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Environment-driven rate-limit settings with sensible defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass

from kestrel.env import getenv, getenv_bool, getenv_int


@dataclass(frozen=True)
class RateLimitSettings:
    """Per-window request caps. Window is shared across all tiers."""

    enabled: bool = True
    window_seconds: int = 60
    # Authenticated general /api/v1/* traffic (per credential hash).
    default_limit: int = 300
    # Sync enqueue, policy fixture evaluate, live connector probes.
    expensive_limit: int = 30
    # Unauthenticated login attempts (per IP); complements account lockout.
    login_limit: int = 20
    # auto | redis | memory — auto prefers Redis when REDIS_URL is set.
    backend: str = "auto"
    redis_url: str | None = None

    def limit_for(self, tier: str) -> int:
        if tier == "expensive":
            return self.expensive_limit
        if tier == "login":
            return self.login_limit
        return self.default_limit


def load_rate_limit_settings() -> RateLimitSettings:
    redis_url = os.environ.get("REDIS_URL") or None
    backend = (getenv("KESTREL_RATE_LIMIT_BACKEND") or "auto").strip().lower()
    if backend not in {"auto", "redis", "memory"}:
        backend = "auto"
    return RateLimitSettings(
        enabled=getenv_bool("KESTREL_RATE_LIMIT_ENABLED", True),
        window_seconds=max(1, getenv_int("KESTREL_RATE_LIMIT_WINDOW_SECONDS", 60)),
        default_limit=max(1, getenv_int("KESTREL_RATE_LIMIT_DEFAULT", 300)),
        expensive_limit=max(1, getenv_int("KESTREL_RATE_LIMIT_EXPENSIVE", 30)),
        login_limit=max(1, getenv_int("KESTREL_RATE_LIMIT_LOGIN", 20)),
        backend=backend,
        redis_url=redis_url,
    )
