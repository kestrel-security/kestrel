# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task wrapping kestrel.sync.pipeline.run_sync -- the durable,
retryable entry point for a connector sync, whether triggered by schedule,
API, or CLI (`kestrel sync --no-async` runs the same pipeline function
in-process instead, for contributors without the full Docker stack running).

Policy evaluation runs as this task's post-processing step, in its own
transaction after the sync commits (``kestrel.sync.execute``), rather than as
a separately enqueued task. A failed evaluation leaves the run marked
``evaluation_pending`` and is not retried; the next sync evaluates in full.

One sync per instance at a time: the task takes the instance lock from
``kestrel.sync.lock`` and skips when it is held. Time limits and retry
classification live on the task decorator so a hung provider call ends as a
FAILED run with a message, not a worker slot pinned for the rest of the day.
"""

from __future__ import annotations

import logging
import uuid

import httpx
from celery.exceptions import SoftTimeLimitExceeded
from kestrel.connectors.sdk.registry import load_connector, load_fixture_transport_builder
from kestrel.db.models.connector import ConnectorInstance, ConnectorRunTrigger, SyncMode
from kestrel.db.session import get_sessionmaker
from kestrel.demo import is_demo_instance
from kestrel.env import getenv_int
from kestrel.sync.execute import record_unfinished_run, start_run, sync_and_evaluate
from kestrel.sync.lock import active_run_for, get_sync_lock
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from kestrel_worker.celery_app import app
from kestrel_worker.tasks.webhooks import deliver_webhook

logger = logging.getLogger(__name__)

# A sync that outlives these is a hung provider call, not a big tenant: the
# soft limit raises inside the task so the run is marked FAILED with a clear
# message, and the hard limit kills the worker child if even that is ignored.
SOFT_TIME_LIMIT_SECONDS = getenv_int("KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS", 1500)
HARD_TIME_LIMIT_SECONDS = max(SOFT_TIME_LIMIT_SECONDS + 60, getenv_int("KESTREL_SYNC_TIME_LIMIT_SECONDS", 1800))

# Only transport-level failures are retried. An authentication or permission
# error retried three times is the same error three times, and a policy or
# database bug retried is three FAILED runs instead of one.
RETRYABLE_ERRORS = (httpx.TransportError, ConnectionError, OperationalError)

SKIPPED_ALREADY_RUNNING = "skipped:already_running"
#: Demo instances are refreshed only by `kestrel demo change` (see kestrel.demo).
SKIPPED_DEMO = "skipped:demo"


@app.task(
    name="kestrel.sync.run_connector_sync",
    bind=True,
    max_retries=3,
    acks_late=True,
    autoretry_for=RETRYABLE_ERRORS,
    retry_backoff=30,
    retry_backoff_max=300,
    retry_jitter=True,
    soft_time_limit=SOFT_TIME_LIMIT_SECONDS,
    time_limit=HARD_TIME_LIMIT_SECONDS,
)
def run_connector_sync(
    self,
    *,
    connector_instance_id: str,
    connector_name: str,
    config: dict,
    secrets: dict[str, str] | None = None,
    triggered_by: str = "manual",
    object_types: list[str] | None = None,
) -> str:
    """Runs one connector sync inside a fresh DB session, then evaluates
    every enabled policy for the org. Returns the resulting ConnectorRun id
    as a string (Celery task results must be JSON-serializable), or
    ``SKIPPED_ALREADY_RUNNING`` when another worker holds the instance.

    `object_types` narrows the run to those families -- the events-only poll.
    The run is marked incremental by `run_sync`, so it is a SUCCESS without
    ever standing in for a full inventory."""
    connector = load_connector(connector_name)
    lock = get_sync_lock()
    token = lock.acquire(connector_instance_id)
    if token is None:
        # Another worker holds this instance. Not an error to retry: the run
        # in progress is the one the operator wants, and the scheduler will
        # come back around.
        logger.info("sync for connector_instance %s skipped: already running", connector_instance_id)
        return SKIPPED_ALREADY_RUNNING
    session = get_sessionmaker()()
    run_id: uuid.UUID | None = None
    try:
        instance = session.get(ConnectorInstance, uuid.UUID(connector_instance_id))
        if instance is None:
            raise ValueError(f"No ConnectorInstance with id {connector_instance_id}")
        # Belt and braces with the lock: a RUNNING row inside the TTL means a
        # worker without lock access (Redis down) is already on it.
        if active_run_for(session, connector_instance_id=instance.id) is not None:
            logger.info("sync for connector_instance %s skipped: RUNNING row inside lock TTL", connector_instance_id)
            return SKIPPED_ALREADY_RUNNING

        if is_demo_instance(instance.config, instance.sync_mode.value):
            logger.info("sync for connector_instance %s skipped: demo instance", connector_instance_id)
            return SKIPPED_DEMO

        # Respect the instance's configured sync mode: fixture-mode
        # instances (e.g. the seeded demo GitHub connector) must never
        # attempt connector.authenticate(), which requires real secrets.
        transport_override = None
        if instance.sync_mode == SyncMode.FIXTURES:
            transport_override = load_fixture_transport_builder(connector_name)()

        effective_config = {**(config or {}), "auth_method": instance.auth_method.value}
        trigger = ConnectorRunTrigger(triggered_by)

        # Committed up front so the API, the UI and the RUNNING-row guard
        # above see this sync while it is in progress.
        run_id = start_run(
            session,
            connector_instance_id=instance.id,
            triggered_by=trigger,
            incremental=object_types is not None,
        ).id
        outcome = sync_and_evaluate(
            session,
            run_id=run_id,
            connector_instance_id=instance.id,
            connector=connector,
            config=effective_config,
            secrets=secrets,
            transport_override=transport_override,
            triggered_by=trigger,
            object_types=object_types,
        )
        for delivery_id in outcome.webhook_delivery_ids:
            deliver_webhook.delay(delivery_id=str(delivery_id))
        return str(outcome.run.id)
    except SoftTimeLimitExceeded:
        # The run is already recorded FAILED with the bare exception text (or
        # still RUNNING if the limit hit between steps); either way, replace
        # it with something an operator can act on. Only this task's run.
        if run_id is not None:
            _mark_timed_out(session, run_id)
        raise
    finally:
        session.close()
        lock.release(connector_instance_id, token)


def _mark_timed_out(session: Session, run_id: uuid.UUID) -> None:
    record_unfinished_run(
        session,
        run_id,
        f"Sync timed out after {SOFT_TIME_LIMIT_SECONDS} seconds (KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS). "
        "The provider stopped answering or the tenant is larger than the time budget allows.",
        overwrite_failed=True,
    )
