# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector / inventory sync health classification for ops hygiene.

Turns last-run timestamps into health states (``HEALTH_STATUSES``) without
live health_check() probes (those remain SDK-only until wired separately).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import Connector, ConnectorInstance, ConnectorRun, ConnectorRunStatus
from kestrel.demo import is_demo_instance

DEFAULT_STALE_AFTER_HOURS = 24
HEALTH_STATUSES = frozenset({"healthy", "degraded", "stale", "failed", "never", "running"})
_FAILED = frozenset({ConnectorRunStatus.FAILED.value})
# Partial coverage is not failure: the run collected, but could not read some
# object type (a plan-gated audit log, a permission the credential lost). It
# gets its own state so a tenant that will *always* be partial -- GitHub Team
# plans have no audit log API -- does not sit permanently red, while still
# never being reported as fully healthy.
_DEGRADED = frozenset({ConnectorRunStatus.PARTIAL_FAILURE.value})
_IN_FLIGHT = frozenset({ConnectorRunStatus.PENDING.value, ConnectorRunStatus.RUNNING.value})


class ConnectorHealthError(ValueError):
    """Invalid health filter / stale threshold."""


def parse_stale_after_hours(raw: int | None) -> int:
    hours = DEFAULT_STALE_AFTER_HOURS if raw is None else raw
    if hours < 1:
        raise ConnectorHealthError("stale_after_hours must be >= 1")
    return hours


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def classify_sync_health(
    *,
    last_run_status: str | None,
    last_success_at: datetime | None,
    now: datetime | None = None,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
) -> str:
    """Classify one connector/application sync posture.

    Priority: never → running → failed → degraded → stale → healthy.
    """
    if last_run_status is None:
        return "never"
    if last_run_status in _IN_FLIGHT:
        return "running"
    if last_run_status in _FAILED:
        return "failed"
    if last_run_status in _DEGRADED:
        return "degraded"

    clock = now or datetime.now(UTC)
    success_at = _aware(last_success_at)
    if success_at is None:
        # Success status without a finished_at is treated as never-fresh.
        return "never"
    age = clock - success_at
    if age > timedelta(hours=stale_after_hours):
        return "stale"
    return "healthy"


def _last_runs_for_instances(
    db: Session, connector_ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, ConnectorRun], dict[uuid.UUID, datetime]]:
    """Latest full run per instance + latest successful finished_at.

    Incremental runs are excluded from both. Connector health asks
    whether Kestrel has a current picture of the tenant, and an events-only
    poll every few minutes does not give one -- it reads audit logs, not
    inventory. Counting them would let a five-minute poll report "success"
    and keep a connector green while its full sync had been failing for days,
    which is precisely the staleness this check exists to catch. Run history
    on the instance page still lists every run.
    """
    last_run: dict[uuid.UUID, ConnectorRun] = {}
    last_success_at: dict[uuid.UUID, datetime] = {}
    if not connector_ids:
        return last_run, last_success_at

    runs = db.scalars(
        select(ConnectorRun)
        .where(
            ConnectorRun.connector_instance_id.in_(connector_ids),
            ConnectorRun.is_incremental.is_(False),
        )
        .order_by(ConnectorRun.started_at.desc())
    ).all()
    for run in runs:
        cid = run.connector_instance_id
        if cid not in last_run:
            last_run[cid] = run
        if cid not in last_success_at and run.status in {
            ConnectorRunStatus.SUCCESS,
            ConnectorRunStatus.PARTIAL_FAILURE,
        }:
            finished = _aware(run.finished_at) or _aware(run.started_at)
            if finished is not None:
                last_success_at[cid] = finished
    return last_run, last_success_at


def connector_health_item(
    db: Session,
    instance: ConnectorInstance,
    *,
    last_run: ConnectorRun | None,
    last_success_at: datetime | None,
    now: datetime | None = None,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
) -> dict:
    """One health row for the connector health center."""
    clock = now or datetime.now(UTC)
    connector_row = db.get(Connector, instance.connector_id)
    app_instance = db.get(ApplicationInstance, instance.application_instance_id)
    last_status = last_run.status.value if last_run else None
    success_at = last_success_at
    if success_at is None and last_run is not None and last_run.status == ConnectorRunStatus.SUCCESS:
        success_at = _aware(last_run.finished_at) or _aware(last_run.started_at)

    health = classify_sync_health(
        last_run_status=last_status,
        last_success_at=success_at,
        now=clock,
        stale_after_hours=stale_after_hours,
    )

    hours_since_success: float | None = None
    if success_at is not None:
        hours_since_success = round((clock - success_at).total_seconds() / 3600.0, 2)

    last_finished = _aware(last_run.finished_at) if last_run else None
    last_started = _aware(last_run.started_at) if last_run else None
    last_run_at = last_finished or last_started

    return {
        "id": instance.id,
        "application_instance_id": instance.application_instance_id,
        "application_display_name": app_instance.display_name if app_instance else None,
        "connector_id": instance.connector_id,
        "connector_name": connector_row.name if connector_row else None,
        "connector_display_name": ((connector_row.manifest or {}).get("display_name") if connector_row else None)
        or (connector_row.name if connector_row else None),
        "auth_method": instance.auth_method.value,
        "sync_mode": instance.sync_mode.value,
        "is_demo": is_demo_instance(instance.config, instance.sync_mode.value),
        "schedule_cron": instance.schedule_cron,
        "last_run_status": last_status,
        "last_run_at": last_run_at.isoformat() if last_run_at is not None else None,
        "last_success_at": success_at.isoformat() if success_at else None,
        "hours_since_success": hours_since_success,
        "health": health,
        "error_summary": last_run.error_summary if last_run else None,
        "last_run_object_counts": last_run.object_counts if last_run else {},
    }


def connector_health_center(
    db: Session,
    org_id: uuid.UUID,
    *,
    health: str | None = None,
    stale_after_hours: int | None = None,
    now: datetime | None = None,
) -> dict:
    """Org-scoped connector health queue + summary counts."""
    threshold = parse_stale_after_hours(stale_after_hours)
    if health is not None and health not in HEALTH_STATUSES:
        raise ConnectorHealthError(f"health must be one of: {', '.join(sorted(HEALTH_STATUSES))}")

    clock = now or datetime.now(UTC)
    # A run stuck on RUNNING past the sync-lock TTL is a dead worker, not an
    # in-flight sync; classify it as the failure it is.
    from kestrel.sync.lock import expire_stale_running_runs

    expire_stale_running_runs(db, org_id=org_id, now=clock)
    instances = list(db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all())
    last_run, last_success = _last_runs_for_instances(db, [i.id for i in instances])

    items = [
        connector_health_item(
            db,
            instance,
            last_run=last_run.get(instance.id),
            last_success_at=last_success.get(instance.id),
            now=clock,
            stale_after_hours=threshold,
        )
        for instance in instances
    ]
    # Unhealthy first: failed → never → stale → running → healthy
    order = {"failed": 0, "never": 1, "stale": 2, "running": 3, "healthy": 4}
    items.sort(key=lambda row: (order.get(row["health"], 9), (row["application_display_name"] or "")))

    summary = dict.fromkeys(sorted(HEALTH_STATUSES), 0)
    for row in items:
        summary[row["health"]] = summary.get(row["health"], 0) + 1

    if health:
        items = [row for row in items if row["health"] == health]

    return {
        "stale_after_hours": threshold,
        "summary": summary,
        "items": items,
        "slo": connector_sync_slo(db, org_id, now=clock, summary=summary, days=7),
    }


def connector_sync_slo(
    db: Session,
    org_id: uuid.UUID,
    *,
    now: datetime | None = None,
    summary: dict[str, int] | None = None,
    days: int = 7,
) -> dict:
    """Labeled sync SLO strip for the health center.

    Honest rates — not an opaque composite score. Targets are documentation
    defaults (95% success / 90% freshness), not contractual SLAs.
    """
    clock = now or datetime.now(UTC)
    window_days = max(1, min(days, 90))
    since = clock - timedelta(days=window_days)

    runs = list(
        db.scalars(
            select(ConnectorRun).where(
                ConnectorRun.org_id == org_id,
                ConnectorRun.started_at.is_not(None),
                ConnectorRun.started_at >= since,
            )
        ).all()
    )
    success = sum(1 for r in runs if r.status == ConnectorRunStatus.SUCCESS)
    failed = sum(1 for r in runs if r.status == ConnectorRunStatus.FAILED)
    degraded_runs = sum(1 for r in runs if r.status == ConnectorRunStatus.PARTIAL_FAILURE)
    total = len(runs)
    # Degraded runs count as neither success nor failure. Folding them into
    # failure would report a working tenant as broken (a GitHub Team plan has
    # no audit log API, so every run is partial); folding them into success
    # would hide the coverage gap entirely.
    success_rate = round((success / total) * 100.0, 1) if total else None

    if summary is None:
        instances = list(db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all())
        last_run, last_success = _last_runs_for_instances(db, [i.id for i in instances])
        summary = dict.fromkeys(sorted(HEALTH_STATUSES), 0)
        for instance in instances:
            h = classify_sync_health(
                last_run_status=last_run[instance.id].status.value if instance.id in last_run else None,
                last_success_at=last_success.get(instance.id),
                now=clock,
            )
            summary[h] = summary.get(h, 0) + 1

    instances_total = sum(summary.get(s, 0) for s in HEALTH_STATUSES)
    healthy = summary.get("healthy", 0)
    degraded = summary.get("degraded", 0)
    # "Unhealthy" is about completeness, so a degraded instance counts.
    unhealthy = instances_total - healthy - summary.get("running", 0)
    # "Freshness" is about recency, so it does not: a degraded run still
    # refreshed the inventory, and marking it stale as well would double-count
    # one problem as two.
    freshness_denom = instances_total - summary.get("running", 0)
    freshness_pct = round(((healthy + degraded) / freshness_denom) * 100.0, 1) if freshness_denom > 0 else None

    success_target = 95.0
    freshness_target = 90.0
    return {
        "window_days": window_days,
        "runs_total": total,
        "runs_success": success,
        "runs_failed": failed,
        "runs_degraded": degraded_runs,
        "success_rate_pct": success_rate,
        "instances_total": instances_total,
        "instances_healthy": healthy,
        "instances_degraded": degraded,
        "instances_unhealthy": max(0, unhealthy),
        "freshness_pct": freshness_pct,
        "success_target_pct": success_target,
        "freshness_target_pct": freshness_target,
        "success_slo_met": success_rate is not None and success_rate >= success_target,
        "freshness_slo_met": freshness_pct is not None and freshness_pct >= freshness_target,
    }
