# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""One sync per connector instance at a time.

Two syncs of the same instance interleaving is the one race the pipeline
cannot tolerate: both compute deletions against the other's half-written
inventory, both emit events for the same diff, and the unique constraints on
relationship rows turn the loser into a FAILED run. Two guards, because
each covers a gap in the other:

* **A Redis lock** (``SET NX EX``) held by the worker for the duration of the
  run. Authoritative between worker processes; expires on its own if a worker
  dies mid-run.
* **The ``connector_runs`` table**, read by the API and the beat dispatcher
  before enqueueing: a RUNNING run younger than the lock TTL means "already in
  progress", so the operator gets a 409 instead of a second queued task, and
  a RUNNING run older than the TTL is a worker that died without finishing and
  is marked FAILED rather than pinning the connector on "running" forever.

Neither guard persists secrets or run data; the lock value is a random token
so a slow worker cannot release a lock a later worker now owns.
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus
from kestrel.env import getenv_int, getenv_str

logger = logging.getLogger(__name__)

DEFAULT_LOCK_TTL_SECONDS = 1800
_ENV_TTL = "KESTREL_SYNC_LOCK_TTL_SECONDS"
_ENV_BACKEND = "KESTREL_SYNC_LOCK_BACKEND"
# The worker task's limits (apps/worker/.../tasks/sync.py reads the same
# variables with the same defaults and the same soft+60 floor).
_ENV_SOFT_TIME_LIMIT = "KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS"
_ENV_HARD_TIME_LIMIT = "KESTREL_SYNC_TIME_LIMIT_SECONDS"
DEFAULT_SOFT_TIME_LIMIT_SECONDS = 1500
DEFAULT_HARD_TIME_LIMIT_SECONDS = 1800
# Headroom between the hard kill and the lock expiring, so the FAILED row the
# task writes on its way out lands while the lock is still held.
_TTL_HEADROOM_SECONDS = 60

# Lua compare-and-delete so a release only removes the lock this holder set.
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


def sync_hard_time_limit_seconds() -> int:
    """The worker's hard task time limit, derived exactly as the task derives it."""
    soft = getenv_int(_ENV_SOFT_TIME_LIMIT, DEFAULT_SOFT_TIME_LIMIT_SECONDS)
    return max(soft + 60, getenv_int(_ENV_HARD_TIME_LIMIT, DEFAULT_HARD_TIME_LIMIT_SECONDS))


def lock_ttl_seconds() -> int:
    """The lock TTL: the configured value, but never shorter than the task can run.

    The TTL and the time limits were independently configurable. A TTL below
    the soft limit let the lock expire mid-run: a second worker started the
    same instance, and `expire_stale_running_runs` marked the live run FAILED.
    The TTL therefore floors at the hard limit plus headroom, whatever is set.
    """
    configured = getenv_int(_ENV_TTL, DEFAULT_LOCK_TTL_SECONDS)
    return max(60, configured, sync_hard_time_limit_seconds() + _TTL_HEADROOM_SECONDS)


def lock_key(connector_instance_id: uuid.UUID | str) -> str:
    return f"kestrel:sync:{connector_instance_id}"


class SyncLock(Protocol):
    def acquire(self, connector_instance_id: uuid.UUID | str) -> str | None:
        """Returns a release token when the lock was taken, None when held elsewhere."""
        ...

    def release(self, connector_instance_id: uuid.UUID | str, token: str) -> None: ...


class InMemorySyncLock:
    """Process-local lock for eager Celery and tests. Honors the TTL so a test
    can observe expiry without a Redis."""

    def __init__(self, ttl_seconds: int | None = None, *, clock: Any = None) -> None:
        self.ttl_seconds = ttl_seconds or lock_ttl_seconds()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._held: dict[str, tuple[str, datetime]] = {}

    def acquire(self, connector_instance_id: uuid.UUID | str) -> str | None:
        key = lock_key(connector_instance_id)
        now = self._clock()
        current = self._held.get(key)
        if current is not None and current[1] > now:
            return None
        token = secrets.token_hex(16)
        self._held[key] = (token, now + timedelta(seconds=self.ttl_seconds))
        return token

    def release(self, connector_instance_id: uuid.UUID | str, token: str) -> None:
        key = lock_key(connector_instance_id)
        current = self._held.get(key)
        if current is not None and current[0] == token:
            del self._held[key]


class RedisSyncLock:
    def __init__(self, redis_url: str, ttl_seconds: int | None = None) -> None:
        import redis

        self.ttl_seconds = ttl_seconds or lock_ttl_seconds()
        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def acquire(self, connector_instance_id: uuid.UUID | str) -> str | None:
        token = secrets.token_hex(16)
        taken = self._redis.set(lock_key(connector_instance_id), token, nx=True, ex=self.ttl_seconds)
        return token if taken else None

    def release(self, connector_instance_id: uuid.UUID | str, token: str) -> None:
        self._redis.eval(_RELEASE_SCRIPT, 1, lock_key(connector_instance_id), token)


class _NoLock:
    """Fail-open stand-in when Redis is unreachable. The database guard still
    applies, so a broker outage degrades to the API-level check rather than
    refusing every sync."""

    def acquire(self, connector_instance_id: uuid.UUID | str) -> str | None:
        return "unlocked"

    def release(self, connector_instance_id: uuid.UUID | str, token: str) -> None:
        return None


_memory_lock: InMemorySyncLock | None = None


def get_sync_lock() -> SyncLock:
    """The lock for this process: Redis in production, in-memory when
    ``KESTREL_SYNC_LOCK_BACKEND=memory`` (eager Celery, tests)."""
    global _memory_lock
    backend = getenv_str(_ENV_BACKEND, "redis").strip().lower()
    if backend == "memory":
        if _memory_lock is None:
            _memory_lock = InMemorySyncLock()
        return _memory_lock
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6380/0")
    try:
        import redis
    except ImportError:  # pragma: no cover - redis ships with the worker and API
        logger.warning("sync lock unavailable (redis is not installed); relying on the connector_runs guard alone")
        return _NoLock()
    try:
        lock = RedisSyncLock(redis_url)
        # A cheap round trip so a dead broker is discovered here, not mid-run.
        lock._redis.ping()
        return lock
    except (redis.RedisError, OSError, ValueError) as exc:  # pragma: no cover - exercised only without Redis
        logger.warning("sync lock unavailable (%s); relying on the connector_runs guard alone", exc)
        return _NoLock()


def expire_stale_running_runs(
    session: Session,
    *,
    org_id: uuid.UUID | None = None,
    connector_instance_id: uuid.UUID | None = None,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
) -> list[ConnectorRun]:
    """Mark RUNNING runs older than the lock TTL as FAILED.

    A run only stays RUNNING past the TTL when its worker died (or was killed
    by the task time limit before it could write the failure). Left alone it
    reads as "syncing" on every page forever and blocks the next sync.
    """
    clock = now or datetime.now(UTC)
    cutoff = clock - timedelta(seconds=ttl_seconds or lock_ttl_seconds())
    stmt = select(ConnectorRun).where(
        ConnectorRun.status == ConnectorRunStatus.RUNNING,
        ConnectorRun.started_at < cutoff,
    )
    if org_id is not None:
        stmt = stmt.where(ConnectorRun.org_id == org_id)
    if connector_instance_id is not None:
        stmt = stmt.where(ConnectorRun.connector_instance_id == connector_instance_id)
    expired = list(session.scalars(stmt).all())
    for run in expired:
        run.status = ConnectorRunStatus.FAILED
        run.finished_at = clock
        run.error_summary = (
            f"Sync did not finish within {int((clock - (run.started_at or cutoff)).total_seconds())} seconds; "
            "the worker stopped reporting and the run was marked failed."
        )
    if expired:
        session.flush()
    return expired


def active_run_for(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
) -> ConnectorRun | None:
    """The RUNNING run for an instance that is still inside the lock TTL."""
    clock = now or datetime.now(UTC)
    cutoff = clock - timedelta(seconds=ttl_seconds or lock_ttl_seconds())
    return session.scalars(
        select(ConnectorRun)
        .where(
            ConnectorRun.connector_instance_id == connector_instance_id,
            ConnectorRun.status == ConnectorRunStatus.RUNNING,
            ConnectorRun.started_at >= cutoff,
        )
        .order_by(ConnectorRun.started_at.desc())
        .limit(1)
    ).first()
