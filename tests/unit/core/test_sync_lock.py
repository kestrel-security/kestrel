# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""``kestrel.sync.lock`` -- the in-memory lock semantics the worker relies on."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kestrel.sync.lock import InMemorySyncLock, lock_key


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def test_a_held_lock_refuses_a_second_holder_until_released():
    lock = InMemorySyncLock(ttl_seconds=60, clock=_Clock())
    token = lock.acquire("instance-1")
    assert token is not None
    assert lock.acquire("instance-1") is None
    # A different instance is unaffected.
    assert lock.acquire("instance-2") is not None
    lock.release("instance-1", token)
    assert lock.acquire("instance-1") is not None


def test_release_with_the_wrong_token_leaves_the_lock_in_place():
    lock = InMemorySyncLock(ttl_seconds=60, clock=_Clock())
    token = lock.acquire("instance-1")
    assert token is not None
    lock.release("instance-1", "not-the-token")
    assert lock.acquire("instance-1") is None


def test_a_lock_expires_after_its_ttl():
    clock = _Clock()
    lock = InMemorySyncLock(ttl_seconds=60, clock=clock)
    assert lock.acquire("instance-1") is not None
    clock.now += timedelta(seconds=61)
    assert lock.acquire("instance-1") is not None


def test_lock_key_is_namespaced_per_instance():
    assert lock_key("abc") == "kestrel:sync:abc"
