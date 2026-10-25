# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The beat dispatcher neither skips nor double-fires a cron tick.

The bug this guards: the dispatcher's window was "the minute before this task
ran". Two executions more than a minute apart (beat drift, or the dispatch task
queued behind long syncs) skipped any fire between them -- a daily cron could
lose a day -- and two executions inside one minute both enqueued.

The fix records the last dispatched fire per instance in Redis (TTL'd, no
schema change) and dispatches the latest fire in ``(last, now]``; a
``SET NX`` claim per (instance, fire) stops two concurrent dispatchers from
both enqueueing it. Without Redis it falls back to the one-minute window.
Pure logic here: the in-memory ledger stands in for Redis.
"""

from __future__ import annotations

# The Celery app registers every task module on import; importing a task module
# first would re-enter that registration half-initialized.
import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
from datetime import UTC, datetime, timedelta

from kestrel_worker.tasks.schedule import (
    CATCHUP_LIMIT,
    InMemoryDispatchLedger,
    RedisDispatchLedger,
    _is_due,
    claim_due_fire,
)

INSTANCE = "00000000-0000-0000-0000-000000000001"


def _at(hour: int, minute: int, *, day: int = 1) -> datetime:
    return datetime(2026, 3, day, hour, minute, tzinfo=UTC)


def test_a_fire_between_two_late_ticks_is_not_skipped():
    # Hourly. Dispatched 11:00; the next ticks ran at 11:59 and 12:01, so no
    # tick fell in the minute ending at 12:00.
    ledger = InMemoryDispatchLedger()
    assert claim_due_fire("0 * * * *", now=_at(11, 0), instance_id=INSTANCE, ledger=ledger) == _at(11, 0)
    assert claim_due_fire("0 * * * *", now=_at(11, 59), instance_id=INSTANCE, ledger=ledger) is None

    assert _is_due("0 * * * *", _at(12, 1)) is False  # the old window misses it
    assert claim_due_fire("0 * * * *", now=_at(12, 1), instance_id=INSTANCE, ledger=ledger) == _at(12, 0)


def test_two_ticks_in_the_same_minute_dispatch_once():
    ledger = InMemoryDispatchLedger()
    first = claim_due_fire("*/5 * * * *", now=_at(9, 5), instance_id=INSTANCE, ledger=ledger)
    second = claim_due_fire("*/5 * * * *", now=_at(9, 5), instance_id=INSTANCE, ledger=ledger)
    assert first == _at(9, 5)
    assert second is None


def test_two_dispatchers_racing_for_one_fire_dispatch_once():
    # Both read the ledger before either claims: the SET NX claim decides.
    ledger = InMemoryDispatchLedger()
    assert ledger.claim(INSTANCE, _at(9, 0)) is True
    assert ledger.claim(INSTANCE, _at(9, 0)) is False


def test_a_missed_day_is_caught_up_once_not_once_per_missed_fire():
    ledger = InMemoryDispatchLedger()
    ledger.claim(INSTANCE, _at(9, 0, day=1))
    # Beat was down until 09:30 on day 2: the 09:00 fire is caught up, once.
    assert claim_due_fire("0 9 * * *", now=_at(9, 30, day=2), instance_id=INSTANCE, ledger=ledger) == _at(9, 0, day=2)
    assert claim_due_fire("0 9 * * *", now=_at(9, 31, day=2), instance_id=INSTANCE, ledger=ledger) is None


def test_catch_up_never_reaches_further_back_than_the_limit():
    # Yearly on 1 March 01:00; last dispatched a year ago. Beat came back an
    # hour past the catch-up limit, so that fire is not dispatched late.
    ledger = InMemoryDispatchLedger()
    ledger.claim(INSTANCE, datetime(2025, 3, 1, 1, 0, tzinfo=UTC))
    now = _at(1, 0) + CATCHUP_LIMIT + timedelta(hours=1)
    assert claim_due_fire("0 1 1 3 *", now=now, instance_id=INSTANCE, ledger=ledger) is None
    # Inside the limit it would have been.
    inside = _at(1, 0) + CATCHUP_LIMIT - timedelta(hours=1)
    assert claim_due_fire("0 1 1 3 *", now=inside, instance_id=INSTANCE, ledger=ledger) == _at(1, 0)


def test_an_instance_with_no_history_uses_the_one_minute_window():
    ledger = InMemoryDispatchLedger()
    assert claim_due_fire("0 9 * * *", now=_at(9, 0), instance_id=INSTANCE, ledger=ledger) == _at(9, 0)
    other = "00000000-0000-0000-0000-000000000002"
    assert claim_due_fire("0 9 * * *", now=_at(9, 5), instance_id=other, ledger=ledger) is None


def test_without_a_ledger_the_old_one_minute_window_applies():
    assert claim_due_fire("0 9 * * *", now=_at(9, 0), instance_id=INSTANCE, ledger=None) == _at(9, 0)
    assert claim_due_fire("0 9 * * *", now=_at(9, 0), instance_id=INSTANCE, ledger=None) == _at(9, 0)
    assert claim_due_fire("0 9 * * *", now=_at(9, 2), instance_id=INSTANCE, ledger=None) is None


def test_a_ledger_that_fails_falls_back_rather_than_blocking_dispatch():
    class _Broken:
        def last_fire(self, instance_id: str) -> datetime | None:
            raise ConnectionError("redis down")

        def claim(self, instance_id: str, fire: datetime) -> bool:
            raise ConnectionError("redis down")

    assert claim_due_fire("0 9 * * *", now=_at(9, 0), instance_id=INSTANCE, ledger=_Broken()) == _at(9, 0)


class _FakeRedis:
    """Just the ``get`` / ``set(nx=, ex=)`` surface the Redis ledger uses."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
        if nx and key in self.values:
            return False
        self.values[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True


def test_the_redis_ledger_claims_once_and_remembers_the_last_fire_with_a_ttl():
    client = _FakeRedis()
    ledger = RedisDispatchLedger(client)

    assert ledger.last_fire(INSTANCE) is None
    assert claim_due_fire("0 * * * *", now=_at(11, 0), instance_id=INSTANCE, ledger=ledger) == _at(11, 0)
    assert ledger.last_fire(INSTANCE) == _at(11, 0)
    assert claim_due_fire("0 * * * *", now=_at(11, 0), instance_id=INSTANCE, ledger=ledger) is None
    assert claim_due_fire("0 * * * *", now=_at(12, 1), instance_id=INSTANCE, ledger=ledger) == _at(12, 0)
    # Every key expires; nothing the ledger writes outlives the catch-up limit.
    assert set(client.ttls) == set(client.values)
    assert set(client.ttls.values()) == {int(CATCHUP_LIMIT.total_seconds())}
