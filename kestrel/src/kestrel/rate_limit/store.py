# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Fixed-window counters: memory store for tests/fallback + shared check helper."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class FixedWindowResult:
    """Outcome of recording one request in the current window."""

    allowed: bool
    limit: int
    count: int
    remaining: int
    retry_after_seconds: int
    reset_at: float  # unix epoch when the window resets


class RateLimitStore(Protocol):
    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Increment the counter for ``key``.

        Returns ``(count, ttl_seconds)`` where ``ttl_seconds`` is seconds until
        the current window expires (at least 1 while the key exists).
        """


class MemoryRateLimitStore:
    """Process-local fixed window. Safe for single-worker / tests only.

    Expired windows are swept out periodically, so a stream of distinct keys
    (one per client IP, say) cannot grow the dict without bound.
    """

    # Sweep at most this often (seconds of monotonic time).
    SWEEP_INTERVAL_SECONDS = 30.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (window_start_monotonic, count, window_seconds)
        self._windows: dict[str, tuple[float, int, int]] = {}
        self._last_sweep = time.monotonic()

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep >= self.SWEEP_INTERVAL_SECONDS:
                self._sweep(now)
            start, count, _ = self._windows.get(key, (now, 0, window_seconds))
            if now - start >= window_seconds:
                start, count = now, 0
            count += 1
            self._windows[key] = (start, count, window_seconds)
            elapsed = now - start
            ttl = max(1, int(window_seconds - elapsed + 0.999))
            return count, ttl

    def _sweep(self, now: float) -> None:
        expired = [key for key, (start, _count, window) in self._windows.items() if now - start >= window]
        for key in expired:
            del self._windows[key]
        self._last_sweep = now

    def __len__(self) -> int:
        with self._lock:
            return len(self._windows)

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()


def check_fixed_window(
    store: RateLimitStore,
    *,
    key: str,
    limit: int,
    window_seconds: int,
    now: float | None = None,
) -> FixedWindowResult:
    """Record one hit and decide allow vs 429."""
    count, ttl = store.increment(key, window_seconds)
    epoch = time.time() if now is None else now
    reset_at = epoch + ttl
    remaining = max(0, limit - count)
    allowed = count <= limit
    return FixedWindowResult(
        allowed=allowed,
        limit=limit,
        count=count,
        remaining=remaining,
        retry_after_seconds=ttl if not allowed else 0,
        reset_at=reset_at,
    )
