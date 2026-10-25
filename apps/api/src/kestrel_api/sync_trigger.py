# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The one way an API route enqueues an on-demand connector sync.

"Sync now" on a connector and "verify, then re-sync" on a finding both start
a sync. Both must refuse a demo instance (a plain sync reads the bundled
sample and deletion detection then removes most of the demo) and an instance
that already has a run in flight, so the guards live here rather than in
each route.
"""

from __future__ import annotations

from fastapi import HTTPException
from kestrel.db.models.connector import Connector, ConnectorInstance
from kestrel.demo import DEMO_SYNC_REFUSAL, is_demo_instance
from kestrel.sync.lock import active_run_for, expire_stale_running_runs
from sqlalchemy.orm import Session

from kestrel_api.tasks_client import TaskQueue


def enqueue_instance_sync(db: Session, instance: ConnectorInstance, tasks: TaskQueue) -> str:
    """Enqueue a sync of ``instance`` and return the task id.

    Raises 409 for a demo instance or one with a run already going, and 503
    when the broker is unreachable. The caller has already checked the
    instance belongs to its org, and records its own audit event.
    """
    connector_row = db.get(Connector, instance.connector_id)
    if connector_row is None:
        raise HTTPException(status_code=500, detail="Connector instance references an unknown connector")
    if is_demo_instance(instance.config, instance.sync_mode.value):
        raise HTTPException(status_code=409, detail=DEMO_SYNC_REFUSAL)

    # A worker that died mid-run must not block the instance forever; a run
    # that is genuinely still going must not be doubled.
    expire_stale_running_runs(db, connector_instance_id=instance.id)
    active = active_run_for(db, connector_instance_id=instance.id)
    if active is not None:
        db.commit()
        raise HTTPException(
            status_code=409,
            detail={
                "message": "A sync for this connector is already running.",
                "run_id": str(active.id),
                "started_at": active.started_at.isoformat() if active.started_at else None,
            },
        )

    try:
        return tasks.enqueue_connector_sync(
            connector_instance_id=str(instance.id),
            connector_name=connector_row.name,
            config=instance.config,
        )
    except Exception as exc:
        from kestrel.secrets.scrub import scrub_text

        raise HTTPException(
            status_code=503,
            detail=f"Could not enqueue sync (is the worker/broker running?): {scrub_text(f'{type(exc).__name__}: {exc}')}",
        ) from exc
