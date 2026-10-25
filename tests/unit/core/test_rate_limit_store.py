# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.rate_limit.store`: `MemoryRateLimitStore` fixed-window counting
and `check_fixed_window`.

`MemoryRateLimitStore.increment` reads `time.monotonic()` internally rather
than accepting an injected clock, so the clock is injected here by
monkeypatching the module's `time.monotonic` -- a controlled fake, never a
real sleep or a wall-clock comparison (docs/testing.md
rule 6 / the qa-unit-engineer brief: "inject a clock, never assert on wall
time").
"""

from __future__ import annotations

from kestrel.rate_limit import store as rate_limit_store
from kestrel.rate_limit.store import FixedWindowResult, MemoryRateLimitStore, check_fixed_window


class _FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


def _store_with_clock(monkeypatch, start: float = 1_000.0) -> tuple[MemoryRateLimitStore, _FakeClock]:
    clock = _FakeClock(start)
    monkeypatch.setattr(rate_limit_store.time, "monotonic", clock)
    return MemoryRateLimitStore(), clock


def test_increment_counts_up_within_a_window(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)

    assert store.increment("key-a", window_seconds=60) == (1, 60)
    assert store.increment("key-a", window_seconds=60) == (2, 60)
    assert store.increment("key-a", window_seconds=60) == (3, 60)


def test_different_keys_have_independent_counters(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)

    assert store.increment("key-a", window_seconds=60) == (1, 60)
    assert store.increment("key-b", window_seconds=60) == (1, 60)
    assert store.increment("key-a", window_seconds=60) == (2, 60)


def test_the_window_resets_the_counter_once_elapsed(monkeypatch):
    store, clock = _store_with_clock(monkeypatch)

    assert store.increment("key-a", window_seconds=60) == (1, 60)
    clock.advance(59)
    count, ttl = store.increment("key-a", window_seconds=60)
    assert count == 2
    assert ttl == 1

    clock.advance(1)  # now 60s after the first hit: window has elapsed
    count, ttl = store.increment("key-a", window_seconds=60)
    assert count == 1
    assert ttl == 60


def test_clear_removes_all_counters(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)
    store.increment("key-a", window_seconds=60)

    store.clear()

    assert store.increment("key-a", window_seconds=60) == (1, 60)


def test_check_fixed_window_allows_up_to_the_limit(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)

    results = [check_fixed_window(store, key="ip:1.2.3.4", limit=3, window_seconds=60, now=1_000.0) for _ in range(3)]

    assert [r.allowed for r in results] == [True, True, True]
    assert [r.count for r in results] == [1, 2, 3]
    assert [r.remaining for r in results] == [2, 1, 0]
    assert all(r.retry_after_seconds == 0 for r in results)


def test_check_fixed_window_denies_once_over_the_limit(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)
    for _ in range(3):
        check_fixed_window(store, key="ip:1.2.3.4", limit=3, window_seconds=60, now=1_000.0)

    result = check_fixed_window(store, key="ip:1.2.3.4", limit=3, window_seconds=60, now=1_000.0)

    assert isinstance(result, FixedWindowResult)
    assert result.allowed is False
    assert result.count == 4
    assert result.remaining == 0
    assert result.retry_after_seconds > 0


def test_check_fixed_window_reset_at_is_derived_from_the_given_now(monkeypatch):
    store, _clock = _store_with_clock(monkeypatch)

    result = check_fixed_window(store, key="ip:1.2.3.4", limit=1, window_seconds=30, now=500.0)

    assert result.reset_at == 500.0 + 30
