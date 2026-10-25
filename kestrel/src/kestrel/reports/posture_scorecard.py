# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org posture scorecard — labeled risk factors only.

Rolls up open criticals, detection gaps, toxic combinations, and stale
connectors into explainable factors. Never an opaque
composite score (see docs/user-experience-principles.md §10; complements
application posture badges).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.connectors.health import DEFAULT_STALE_AFTER_HOURS, classify_sync_health
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Severity
from kestrel.reports.detection_coverage import detection_gap_count
from kestrel.reports.toxic_combinations import toxic_combination_count


def _factor(
    *,
    key: str,
    label: str,
    tone: str,
    detail: str,
    count: int,
    href: str,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "tone": tone,
        "detail": detail,
        "count": count,
        "href": href,
    }


def build_scorecard_factors(
    *,
    open_critical: int,
    detection_gaps: int,
    toxic_combinations: int,
    stale_connectors: int,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
    never_synced: int = 0,
    last_sync_failed: int = 0,
) -> list[dict[str, Any]]:
    """Assemble labeled factors from already-computed counts (no scoring)."""
    factors: list[dict[str, Any]] = []

    if open_critical > 0:
        factors.append(
            _factor(
                key="open_criticals",
                label=f"{open_critical} open critical",
                tone="critical",
                detail=f"{open_critical} open finding(s) at critical severity",
                count=open_critical,
                href="/findings?status=open&severity=critical",
            )
        )
    else:
        factors.append(
            _factor(
                key="open_criticals",
                label="No open criticals",
                tone="ok",
                detail="No open findings at critical severity",
                count=0,
                href="/findings?status=open&severity=critical",
            )
        )

    if detection_gaps > 0:
        factors.append(
            _factor(
                key="detection_gaps",
                label=f"{detection_gaps} detection gap{'s' if detection_gaps != 1 else ''}",
                tone="warn",
                detail=(
                    f"{detection_gaps} connected application instance(s) lack applicable "
                    "enabled policies or have never matched"
                ),
                count=detection_gaps,
                href="/policies/packs",
            )
        )
    else:
        factors.append(
            _factor(
                key="detection_gaps",
                label="Detection coverage clear",
                tone="ok",
                detail="Every connected instance has applicable policies with prior matches",
                count=0,
                href="/policies/packs",
            )
        )

    if toxic_combinations > 0:
        factors.append(
            _factor(
                key="toxic_combinations",
                label=f"{toxic_combinations} toxic combo{'s' if toxic_combinations != 1 else ''}",
                tone="high",
                detail=(f"{toxic_combinations} named attack-path combination(s) over open findings"),
                count=toxic_combinations,
                href="/findings?status=open",
            )
        )
    else:
        factors.append(
            _factor(
                key="toxic_combinations",
                label="No toxic combinations",
                tone="ok",
                detail="No named attack-path rules matched open findings",
                count=0,
                href="/findings?status=open",
            )
        )

    if stale_connectors > 0:
        extra = ""
        if last_sync_failed or never_synced:
            extra = f"; also {last_sync_failed} failed, {never_synced} never synced"
        factors.append(
            _factor(
                key="stale_connectors",
                label=f"{stale_connectors} stale connector{'s' if stale_connectors != 1 else ''}",
                tone="warn",
                detail=(
                    f"{stale_connectors} application(s) with last successful sync older than {stale_after_hours}h{extra}"
                ),
                count=stale_connectors,
                href="/connectors/health?health=stale",
            )
        )
    elif last_sync_failed > 0:
        factors.append(
            _factor(
                key="stale_connectors",
                label=f"{last_sync_failed} sync failure{'s' if last_sync_failed != 1 else ''}",
                tone="critical",
                detail=f"{last_sync_failed} application(s) with last sync failed",
                count=last_sync_failed,
                href="/connectors/health?health=failed",
            )
        )
    elif never_synced > 0:
        factors.append(
            _factor(
                key="stale_connectors",
                label=f"{never_synced} never synced",
                tone="neutral",
                detail=f"{never_synced} application(s) have never completed a successful sync",
                count=never_synced,
                href="/connectors/health?health=never",
            )
        )
    else:
        factors.append(
            _factor(
                key="stale_connectors",
                label="Connectors healthy",
                tone="ok",
                detail=f"All connected applications synced within the last {stale_after_hours}h",
                count=0,
                href="/connectors/health",
            )
        )

    return factors


def _open_critical_count(db: Session, org_id: uuid.UUID) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.OPEN,
                Finding.severity == Severity.CRITICAL,
            )
        )
        or 0
    )


def inventory_sync_counts(
    db: Session, org_id: uuid.UUID, *, stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS
) -> dict[str, int]:
    """Stale / failed / never_synced counts (same classifier as dashboard)."""
    instances = list(db.scalars(select(ApplicationInstance).where(ApplicationInstance.org_id == org_id)).all())
    if not instances:
        return {"stale": 0, "never_synced": 0, "last_sync_failed": 0, "stale_after_hours": stale_after_hours}

    connector_by_app = {
        ci.application_instance_id: ci
        for ci in db.scalars(
            select(ConnectorInstance).where(
                ConnectorInstance.org_id == org_id,
                ConnectorInstance.application_instance_id.in_([i.id for i in instances]),
            )
        ).all()
    }
    last_run_by_connector: dict[uuid.UUID, ConnectorRun] = {}
    last_success_by_connector: dict[uuid.UUID, datetime] = {}
    connector_ids = [c.id for c in connector_by_app.values()]
    if connector_ids:
        runs = db.scalars(
            select(ConnectorRun)
            .where(ConnectorRun.connector_instance_id.in_(connector_ids))
            .order_by(ConnectorRun.started_at.desc())
        ).all()
        for run in runs:
            if run.connector_instance_id not in last_run_by_connector:
                last_run_by_connector[run.connector_instance_id] = run
            if run.connector_instance_id not in last_success_by_connector and run.status == ConnectorRunStatus.SUCCESS:
                finished = run.finished_at or run.started_at
                if finished is not None:
                    last_success_by_connector[run.connector_instance_id] = finished

    clock = datetime.now(UTC)
    never_synced = 0
    last_sync_failed = 0
    stale = 0
    for instance in instances:
        connector = connector_by_app.get(instance.id)
        if connector is None:
            never_synced += 1
            continue
        last_run = last_run_by_connector.get(connector.id)
        status = last_run.status.value if last_run else None
        health = classify_sync_health(
            last_run_status=status,
            last_success_at=last_success_by_connector.get(connector.id),
            now=clock,
            stale_after_hours=stale_after_hours,
        )
        if health == "never":
            never_synced += 1
        elif health == "failed":
            last_sync_failed += 1
        elif health == "stale":
            stale += 1

    return {
        "stale": stale,
        "never_synced": never_synced,
        "last_sync_failed": last_sync_failed,
        "stale_after_hours": stale_after_hours,
    }


def posture_scorecard_report(db: Session, org_id: uuid.UUID) -> dict[str, Any]:
    """Labeled factors for ``org_id``; feeds the daily posture-trend snapshot."""
    sync = inventory_sync_counts(db, org_id)
    factors = build_scorecard_factors(
        open_critical=_open_critical_count(db, org_id),
        detection_gaps=detection_gap_count(db, org_id),
        toxic_combinations=toxic_combination_count(db, org_id),
        stale_connectors=int(sync["stale"]),
        stale_after_hours=int(sync["stale_after_hours"]),
        never_synced=int(sync["never_synced"]),
        last_sync_failed=int(sync["last_sync_failed"]),
    )
    attention = sum(1 for f in factors if f["tone"] in {"critical", "high", "warn"})
    return {
        "as_of": datetime.now(UTC).isoformat(),
        "factor_count": len(factors),
        "attention_count": attention,
        "factors": factors,
    }
