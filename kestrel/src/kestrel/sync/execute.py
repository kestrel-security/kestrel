# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The run lifecycle around ``run_sync`` shared by the worker task and
``kestrel sync --no-async``.

1. ``start_run`` commits a RUNNING ``ConnectorRun`` in its own short
   transaction, so other sessions see the sync in progress (the UI, the API's
   409 guard, ``expire_stale_running_runs``).
2. ``sync_and_evaluate`` runs the sync and commits it, so the run reads
   finished (and its correlation lock is released) as soon as collection is
   done. It then evaluates policies, when the run collected anything usable
   (SUCCESS or PARTIAL_FAILURE), in a transaction of its own. Evaluation can
   take minutes; holding the sync open for it kept the run "Running" and
   blocked other syncs on the evaluation lock.
3. Whatever fails, the run ends recorded: ``run_sync``'s own FAILED row is
   committed; a commit that itself fails marks the run FAILED via
   ``record_unfinished_run``, which only ever touches that run; and a failed
   evaluation keeps the synced inventory and notes the failure on the run.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import Connector, Transport
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.findings.pipeline import evaluate_all_enabled_policies, evaluation_plan_for_run
from kestrel.secrets.scrub import scrub_text
from kestrel.sync.pipeline import run_sync

logger = logging.getLogger(__name__)

#: Statuses whose inventory is worth evaluating. A partial run could not read
#: one family (e.g. an audit log the plan lacks) but collected the rest of the
#: tenant; skipping evaluation would leave that org with no findings at all.
#: Deletion detection is already suppressed for it, so nothing false-resolves.
EVALUATED_STATUSES = frozenset({ConnectorRunStatus.SUCCESS, ConnectorRunStatus.PARTIAL_FAILURE})


@dataclass
class SyncOutcome:
    run: ConnectorRun
    webhook_delivery_ids: list[uuid.UUID] = field(default_factory=list)


def start_run(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
    triggered_by: ConnectorRunTrigger = ConnectorRunTrigger.MANUAL,
    incremental: bool = False,
) -> ConnectorRun:
    """Insert and commit a RUNNING run for the instance.

    Commits ``session``: call it on a session that holds nothing else
    uncommitted.
    """
    instance = session.get(ConnectorInstance, connector_instance_id)
    if instance is None:
        raise ValueError(f"No ConnectorInstance with id {connector_instance_id}")
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=ConnectorRunStatus.RUNNING,
        started_at=datetime.now(UTC),
        triggered_by=triggered_by,
        is_incremental=incremental,
    )
    session.add(run)
    session.commit()
    return run


def record_unfinished_run(session: Session, run_id: uuid.UUID, summary: str, *, overwrite_failed: bool = False) -> None:
    """Roll back, then mark ``run_id`` FAILED if its outcome never committed.

    After the rollback a run reads RUNNING exactly when nothing recorded how it
    ended. A run that already committed SUCCESS or PARTIAL_FAILURE is left
    alone (the failure came after its work was saved, e.g. a broker outage
    while enqueueing webhooks). ``overwrite_failed`` replaces the summary of a
    run already recorded FAILED, for a cause more actionable than the
    exception text (a time limit). Never raises: it runs inside error paths.
    """
    try:
        session.rollback()
        run = session.get(ConnectorRun, run_id)
        if run is None:
            return
        if run.status is ConnectorRunStatus.RUNNING or (overwrite_failed and run.status is ConnectorRunStatus.FAILED):
            run.status = ConnectorRunStatus.FAILED
            run.finished_at = datetime.now(UTC)
            run.error_summary = summary[:2000]
            session.commit()
    except SQLAlchemyError:
        logger.warning("sync.record_failure_failed", extra={"connector_run_id": str(run_id)}, exc_info=True)
        try:
            session.rollback()
        except SQLAlchemyError:
            logger.warning("sync.rollback_failed", exc_info=True)


def sync_and_evaluate(
    session: Session,
    *,
    run_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
    connector: Connector,
    config: dict,
    secrets: dict[str, str] | None = None,
    transport_override: Transport | None = None,
    triggered_by: ConnectorRunTrigger = ConnectorRunTrigger.MANUAL,
    object_types: list[str] | None = None,
) -> SyncOutcome:
    """Sync into the run ``start_run`` created and commit it, then evaluate.

    Webhook deliveries are returned rather than sent: the caller dispatches
    them after the commit, its own way (Celery, or inline for the CLI).
    """
    try:
        run = run_sync(
            session,
            connector_instance_id=connector_instance_id,
            connector=connector,
            config=config,
            secrets=secrets,
            transport_override=transport_override,
            triggered_by=triggered_by,
            object_types=object_types,
            run_id=run_id,
        )
    except Exception as exc:
        # run_sync has rolled back and flushed the run as FAILED with a
        # scrubbed summary; persist it.
        try:
            session.commit()
        except SQLAlchemyError:
            record_unfinished_run(session, run_id, scrub_text(f"{type(exc).__name__}: {exc}", (secrets or {}).values()))
        raise

    # Committed together with the sync: if evaluation never completes, the
    # next sync in the org sees the debt and evaluates in full.
    run.evaluation_pending = run.status in EVALUATED_STATUSES
    try:
        session.commit()
    except SQLAlchemyError as exc:
        record_unfinished_run(session, run_id, scrub_text(f"{type(exc).__name__}: {exc}", (secrets or {}).values()))
        raise

    outcome = SyncOutcome(run=run)
    try:
        # Partial coverage still evaluates: a run that could not read one
        # plan-gated family collected the rest of the tenant. An audit-log poll
        # that changed no inventory re-evaluates only activity policies, or
        # nothing when it brought no new activity.
        plan = evaluation_plan_for_run(session, run) if run.status in EVALUATED_STATUSES else None
        if plan is not None and plan.evaluate:
            evaluate_all_enabled_policies(
                session,
                org_id=run.org_id,
                connector_run_id=run.id,
                webhook_delivery_ids=outcome.webhook_delivery_ids,
                resource_types=plan.resource_types,
            )
        if plan is not None:
            _settle_evaluation_debt(session, run, covered_all=plan.resource_types is None)
        session.commit()
    except Exception as exc:
        summary = scrub_text(
            f"Synced, but policy evaluation failed; findings were not updated: {type(exc).__name__}: {exc}",
            (secrets or {}).values(),
        )
        _record_evaluation_failure(session, run_id, summary)
        # Not a retryable error, whatever caused it: the sync is committed,
        # so a retry would only re-collect. The next sync evaluates in full.
        raise PostSyncEvaluationError(summary) from exc
    return outcome


class PostSyncEvaluationError(RuntimeError):
    """Policy evaluation failed after the sync it follows had committed."""


def _settle_evaluation_debt(session: Session, run: ConnectorRun, *, covered_all: bool) -> None:
    """A full evaluation covers every sync the org committed before it; a
    narrower one (or none, when nothing changed) settles only this run."""
    if covered_all:
        session.execute(
            update(ConnectorRun)
            .where(
                ConnectorRun.org_id == run.org_id,
                ConnectorRun.evaluation_pending.is_(True),
                ConnectorRun.started_at <= run.started_at,
            )
            .values(evaluation_pending=False)
        )
    run.evaluation_pending = False


def _record_evaluation_failure(session: Session, run_id: uuid.UUID, summary: str) -> None:
    """Note a failed evaluation on a run whose sync already committed. Never raises."""
    try:
        session.rollback()
        run = session.get(ConnectorRun, run_id)
        if run is not None:
            run.error_summary = summary[:2000]
            run.evaluation_pending = True
            session.commit()
    except SQLAlchemyError:
        logger.warning("sync.record_evaluation_failure_failed", extra={"connector_run_id": str(run_id)}, exc_info=True)
        try:
            session.rollback()
        except SQLAlchemyError:
            logger.warning("sync.rollback_failed", exc_info=True)
