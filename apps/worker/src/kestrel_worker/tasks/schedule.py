# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Turns ConnectorInstance.schedule_cron (a per-tenant DB column) into
actual sync enqueues, plus the separate events-only poll.

Celery's static `app.conf.beat_schedule` can't itself vary per DB row, so
instead of one beat entry per instance, beat_schedule.py registers a single
dispatcher entry that fires this task once a minute; this task is the one
place that reads schedule_cron and decides who's due.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from croniter import CroniterBadCronError, CroniterBadDateError, croniter
from kestrel.db.models.connector import Connector, ConnectorInstance
from kestrel.db.session import get_sessionmaker
from kestrel.env import getenv_str
from kestrel.sync.cursors import incremental_object_types
from kestrel.sync.lock import active_run_for
from redis.exceptions import RedisError
from sqlalchemy import select

from kestrel_worker.celery_app import app
from kestrel_worker.tasks.sync import run_connector_sync

logger = logging.getLogger(__name__)

# Must match (or be >=) the beat interval in beat_schedule.py -- this window
# is what makes a fire time from up to a minute ago still count as "due
# now" even though this task itself runs on a fixed cadence rather than at
# the cron expression's exact second. It is the whole lookback when there is
# no dispatch ledger (Redis unavailable, or an instance with no history).
DISPATCH_WINDOW = timedelta(minutes=1)

# How far back a missed fire is still dispatched late, and how long the
# ledger remembers an instance's last dispatched fire. A schedule whose
# period is longer than this falls back to the one-minute window.
CATCHUP_LIMIT = timedelta(hours=24)

_LAST_KEY = "kestrel:schedule:last:{instance_id}"
_CLAIM_KEY = "kestrel:schedule:fired:{instance_id}:{fire}"
_ENV_BACKEND = "KESTREL_SYNC_LOCK_BACKEND"

# What a ledger can raise when Redis is unreachable or misconfigured (a bad
# URL is a ValueError) or holds an unparseable fire time (also ValueError).
# Any of these degrades to the one-minute window rather than skipping a tick.
_LEDGER_ERRORS = (RedisError, OSError, ValueError)


class DispatchLedger(Protocol):
    """Per-instance record of dispatched cron fires.

    Lives in Redis rather than a ``connector_instances`` column so the fix
    needs no schema change; losing it (a Redis flush) costs at most the
    one-minute-window behaviour, never a duplicate.
    """

    def last_fire(self, instance_id: str) -> datetime | None:
        """The most recent fire dispatched for this instance, if remembered."""
        ...

    def claim(self, instance_id: str, fire: datetime) -> bool:
        """Atomically claim ``fire`` for dispatch and record it as the last
        fire. False when another dispatcher already claimed it."""
        ...


class RedisDispatchLedger:
    def __init__(self, client: Any, ttl: timedelta = CATCHUP_LIMIT) -> None:
        self._redis = client
        self._ttl_seconds = int(ttl.total_seconds())

    def last_fire(self, instance_id: str) -> datetime | None:
        raw = self._redis.get(_LAST_KEY.format(instance_id=instance_id))
        if raw is None:
            return None
        value = raw.decode() if isinstance(raw, bytes) else str(raw)
        return datetime.fromisoformat(value)

    def claim(self, instance_id: str, fire: datetime) -> bool:
        claimed = self._redis.set(
            _CLAIM_KEY.format(instance_id=instance_id, fire=fire.isoformat()),
            "1",
            nx=True,
            ex=self._ttl_seconds,
        )
        if not claimed:
            return False
        self._redis.set(_LAST_KEY.format(instance_id=instance_id), fire.isoformat(), ex=self._ttl_seconds)
        return True


class InMemoryDispatchLedger:
    """Process-local ledger for eager Celery and tests."""

    def __init__(self) -> None:
        self._last: dict[str, datetime] = {}
        self._claimed: set[tuple[str, datetime]] = set()

    def last_fire(self, instance_id: str) -> datetime | None:
        return self._last.get(instance_id)

    def claim(self, instance_id: str, fire: datetime) -> bool:
        if (instance_id, fire) in self._claimed:
            return False
        self._claimed.add((instance_id, fire))
        previous = self._last.get(instance_id)
        if previous is None or fire > previous:
            self._last[instance_id] = fire
        return True


_memory_ledger: InMemoryDispatchLedger | None = None


def get_dispatch_ledger() -> DispatchLedger | None:
    """Redis in production; in-memory under the same ``memory`` backend switch
    the sync lock uses; None (one-minute-window fallback) when Redis is down."""
    global _memory_ledger
    if getenv_str(_ENV_BACKEND, "redis").strip().lower() == "memory":
        if _memory_ledger is None:
            _memory_ledger = InMemoryDispatchLedger()
        return _memory_ledger
    try:
        import redis

        client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6380/0"), decode_responses=True)
        client.ping()
        return RedisDispatchLedger(client)
    except _LEDGER_ERRORS as exc:
        logger.warning("schedule dispatch ledger unavailable (%s); using the one-minute dispatch window", exc)
        return None


def _latest_fire(cron_expr: str, *, after: datetime, now: datetime) -> datetime | None:
    """The latest fire time in ``(after, now]``, or None."""
    # croniter's get_prev is strictly before its start; fires are whole
    # minutes, so starting a second past ``now`` includes a fire at ``now``.
    latest: datetime = croniter(cron_expr, now + timedelta(seconds=1)).get_prev(datetime)
    return latest if latest > after else None


def _is_due(cron_expr: str, now: datetime) -> bool:
    """True if `cron_expr` has a scheduled fire time within the dispatch
    window ending at `now`."""
    return _latest_fire(cron_expr, after=now - DISPATCH_WINDOW, now=now) is not None


def claim_due_fire(
    cron_expr: str,
    *,
    now: datetime,
    instance_id: str,
    ledger: DispatchLedger | None,
) -> datetime | None:
    """The fire this tick should dispatch for an instance, claimed; else None.

    With a ledger, the window is ``(last dispatched fire, now]`` (no further
    back than ``CATCHUP_LIMIT``), so a fire that fell between two late ticks
    is still dispatched, once, and a second tick in the same minute finds
    nothing new. Several missed fires coalesce into one sync: the latest. The
    claim is a ``SET NX`` per (instance, fire), so two dispatchers racing on
    one fire enqueue it once. Without a ledger, or if it errors, this is the
    old one-minute window. Raises for an invalid cron expression.
    """
    after = now - DISPATCH_WINDOW
    if ledger is not None:
        try:
            last = ledger.last_fire(instance_id)
        except _LEDGER_ERRORS as exc:
            logger.warning("schedule dispatch ledger read failed (%s); using the one-minute window", exc)
            ledger = None
        else:
            if last is not None:
                after = max(last, now - CATCHUP_LIMIT)

    fire = _latest_fire(cron_expr, after=after, now=now)
    if fire is None or ledger is None:
        return fire
    try:
        return fire if ledger.claim(instance_id, fire) else None
    except _LEDGER_ERRORS as exc:
        logger.warning("schedule dispatch ledger claim failed (%s); dispatching without it", exc)
        return fire


@app.task(name="kestrel.schedule.dispatch_scheduled_syncs")
def dispatch_scheduled_syncs() -> int:
    """Enqueues a sync for every ConnectorInstance whose schedule_cron has a
    fire due since its last dispatch (see ``claim_due_fire``). Returns the
    number enqueued.

    Known limitation: missed fires are caught up only within
    ``CATCHUP_LIMIT``, only while Redis remembers the last dispatch, and as
    one sync however many fires were missed. Without Redis the dispatcher
    falls back to the fires in the minute before it ran, which can skip a fire
    when ticks drift more than a minute apart or double-fire when two land in
    one minute.
    """
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    ledger = get_dispatch_ledger()
    session = get_sessionmaker()()
    dispatched = 0
    try:
        instances = session.scalars(select(ConnectorInstance).where(ConnectorInstance.schedule_cron.is_not(None))).all()
        for instance in instances:
            cron = instance.schedule_cron
            if cron is None:
                # The query filters these out; belt and braces if it ever changes.
                continue
            try:
                fire = claim_due_fire(cron, now=now, instance_id=str(instance.id), ledger=ledger)
            except (CroniterBadCronError, CroniterBadDateError, ValueError) as exc:
                logger.warning(
                    "connector_instance %s has an invalid schedule_cron %r, skipping: %s",
                    instance.id,
                    instance.schedule_cron,
                    exc,
                )
                continue
            if fire is None:
                continue

            connector = session.get(Connector, instance.connector_id)
            if connector is None:
                logger.warning(
                    "connector_instance %s references unknown connector %s, skipping",
                    instance.id,
                    instance.connector_id,
                )
                continue

            # The fire is already claimed, so a sync in progress consumes it
            # rather than queueing a second one for when it finishes.
            if active_run_for(session, connector_instance_id=instance.id) is not None:
                logger.info("connector_instance %s is already syncing; skipping this tick", instance.id)
                continue
            run_connector_sync.delay(
                connector_instance_id=str(instance.id),
                connector_name=connector.name,
                config=instance.config,
                triggered_by="schedule",
            )
            dispatched += 1
    finally:
        session.close()
    return dispatched


@app.task(name="kestrel.schedule.dispatch_event_syncs")
def dispatch_event_syncs() -> int:
    """Enqueues a cursored events-only sync for every eligible instance.

    Eligible means the instance is on an automatic schedule (`schedule_cron`
    set -- polling an instance the operator only ever syncs by hand would be a
    surprise) and its connector's manifest declares at least one object type
    with ``supports_incremental``.

    This is the reason `Collector.collect(since=)` exists. Audit logs are
    append-only and cursored, so they can be re-read every few minutes at a
    fraction of the cost of the directory walk that `schedule_cron` governs --
    which is why this is a separate beat entry rather than a faster default
    for everyone.

    The enqueued run collects *only* those object types. `run_sync` marks it
    incremental, which suppresses deletion detection and snapshotting and
    keeps it from being mistaken for a full inventory.
    """
    session = get_sessionmaker()()
    dispatched = 0
    try:
        instances = session.scalars(select(ConnectorInstance).where(ConnectorInstance.schedule_cron.is_not(None))).all()
        connectors: dict[uuid.UUID, Connector | None] = {}
        for instance in instances:
            if instance.connector_id not in connectors:
                connectors[instance.connector_id] = session.get(Connector, instance.connector_id)
            connector = connectors[instance.connector_id]
            if connector is None:
                logger.warning(
                    "connector_instance %s references unknown connector %s, skipping",
                    instance.id,
                    instance.connector_id,
                )
                continue

            object_types = incremental_object_types(connector.manifest or {})
            if not object_types:
                continue
            if active_run_for(session, connector_instance_id=instance.id) is not None:
                continue

            run_connector_sync.delay(
                connector_instance_id=str(instance.id),
                connector_name=connector.name,
                config=instance.config,
                triggered_by="schedule",
                object_types=object_types,
            )
            dispatched += 1
    finally:
        session.close()
    return dispatched
