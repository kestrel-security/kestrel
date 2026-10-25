# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-scoped SSPM dashboard: findings metrics, connector health, top failing policies."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from kestrel.connectors.health import DEFAULT_STALE_AFTER_HOURS, classify_sync_health
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Policy, PolicyVersion, Severity
from kestrel.findings.listing import open_findings_by_age, ownership_queues
from kestrel.webhooks.history import org_delivery_counts

RECENT_OPEN_LIMIT = 8
TOP_FAILING_POLICIES = 8
QUEUE_PREVIEW_LIMIT = 5


def _count_map(rows: Sequence[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, count in rows:
        label = key.value if hasattr(key, "value") else str(key)
        out[label] = int(count)
    return out


def _finding_preview_item(finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
    }


def _open_queue_preview(
    db: Session,
    org_id: uuid.UUID,
    *,
    assigned_to_operator_id: uuid.UUID | None = None,
    unassigned: bool = False,
    limit: int = QUEUE_PREVIEW_LIMIT,
) -> list[dict]:
    stmt = select(Finding).where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
    if unassigned:
        stmt = stmt.where(Finding.assigned_to_operator_id.is_(None))
    elif assigned_to_operator_id is not None:
        stmt = stmt.where(Finding.assigned_to_operator_id == assigned_to_operator_id)
    else:
        return []
    findings = list(db.scalars(stmt.order_by(Finding.last_seen_at.desc(), Finding.id.desc()).limit(limit)).all())
    return [_finding_preview_item(f) for f in findings]


def _findings_rollup(
    db: Session,
    org_id: uuid.UUID,
    *,
    viewer_operator_id: uuid.UUID | None = None,
) -> dict:
    by_status_rows = db.execute(
        select(Finding.status, func.count()).where(Finding.org_id == org_id).group_by(Finding.status)
    ).all()
    by_status = {s.value: 0 for s in FindingStatus}
    by_status.update(_count_map(by_status_rows))

    open_by_severity_rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    ).all()
    by_severity = {s.value: 0 for s in Severity}
    by_severity.update(_count_map(open_by_severity_rows))

    # One row per policy. Every finding from a single evaluation shares a
    # `last_seen_at`, so ordering by time alone lets one policy fill the whole
    # widget -- the dashboard showed four copies of the same title, which says
    # strictly less than four different ones in the same space. DISTINCT ON
    # takes each policy's most recent open finding, then the newest of those.
    newest_per_policy = (
        select(Finding)
        .where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
        .distinct(Finding.policy_version_id)
        .order_by(Finding.policy_version_id, Finding.last_seen_at.desc(), Finding.id.desc())
        .subquery()
    )
    aliased_finding = aliased(Finding, newest_per_policy)
    recent = list(
        db.scalars(
            select(aliased_finding)
            .order_by(aliased_finding.last_seen_at.desc(), aliased_finding.id.desc())
            .limit(RECENT_OPEN_LIMIT)
        ).all()
    )
    ownership = ownership_queues(db, org_id, viewer_operator_id=viewer_operator_id)
    out: dict[str, Any] = {
        "open_total": by_status.get(FindingStatus.OPEN.value, 0),
        "by_status": by_status,
        "open_by_severity": by_severity,
        "open_by_age": open_findings_by_age(db, org_id),
        "ownership": ownership,
        "recent_open": [_finding_preview_item(f) for f in recent],
        "mine_preview": (
            _open_queue_preview(db, org_id, assigned_to_operator_id=viewer_operator_id)
            if viewer_operator_id is not None
            else []
        ),
        "unassigned_preview": _open_queue_preview(db, org_id, unassigned=True),
    }
    if viewer_operator_id is not None:
        out["viewer_operator_id"] = str(viewer_operator_id)
    return out


def _connector_health_rollup(
    db: Session,
    org_id: uuid.UUID,
    *,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
) -> dict:
    connectors = list(db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all())
    total = len(connectors)
    if total == 0:
        return {
            "connector_count": 0,
            "healthy": 0,
            "never_synced": 0,
            "failed": 0,
            "stale": 0,
            "running": 0,
            "stale_after_hours": stale_after_hours,
        }

    last_run_by_connector: dict[uuid.UUID, ConnectorRun] = {}
    last_success_by_connector: dict[uuid.UUID, datetime] = {}
    connector_ids = [c.id for c in connectors]
    # DISTINCT ON (connector_instance_id) — one row per connector, not the
    # full run history. Loading every run made GET /dashboard scale with
    # sync count rather than connector count.
    last_runs = db.scalars(
        select(ConnectorRun)
        .where(ConnectorRun.connector_instance_id.in_(connector_ids))
        .distinct(ConnectorRun.connector_instance_id)
        .order_by(ConnectorRun.connector_instance_id, ConnectorRun.started_at.desc())
    ).all()
    for run in last_runs:
        last_run_by_connector[run.connector_instance_id] = run
    last_successes = db.scalars(
        select(ConnectorRun)
        .where(
            ConnectorRun.connector_instance_id.in_(connector_ids),
            ConnectorRun.status == ConnectorRunStatus.SUCCESS,
        )
        .distinct(ConnectorRun.connector_instance_id)
        .order_by(ConnectorRun.connector_instance_id, ConnectorRun.started_at.desc())
    ).all()
    for run in last_successes:
        finished = run.finished_at or run.started_at
        if finished is not None:
            last_success_by_connector[run.connector_instance_id] = finished

    clock = datetime.now(UTC)
    healthy = never_synced = failed = stale = running = 0
    for connector in connectors:
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
            failed += 1
        elif health == "stale":
            stale += 1
        elif health == "healthy":
            healthy += 1
        elif health == "running":
            running += 1

    return {
        "connector_count": total,
        "healthy": healthy,
        "never_synced": never_synced,
        "failed": failed,
        "stale": stale,
        "running": running,
        "stale_after_hours": stale_after_hours,
    }


def _top_failing_policies(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        select(Policy.id, Policy.slug, Policy.title, PolicyVersion.severity, func.count(Finding.id))
        .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
        .join(Policy, Policy.id == PolicyVersion.policy_id)
        .where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
        .group_by(Policy.id, Policy.slug, Policy.title, PolicyVersion.severity)
        .order_by(func.count(Finding.id).desc())
        .limit(TOP_FAILING_POLICIES)
    ).all()
    return [
        {
            "policy_id": str(policy_id),
            "slug": slug,
            "title": title,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "open_count": int(count),
        }
        for policy_id, slug, title, severity, count in rows
    ]


def _first_run_checklist(
    db: Session, org_id: uuid.UUID, connectors: dict, findings: dict, *, dismissed: bool = False
) -> dict:
    connector_count = int(connectors.get("connector_count") or 0)
    pack_policy_count = db.scalar(select(func.count()).select_from(Policy).where(Policy.org_id == org_id)) or 0
    has_connector = connector_count > 0
    has_pack = int(pack_policy_count) > 0
    has_sync = int(connectors.get("healthy") or 0) > 0
    has_findings = int(findings.get("open_total") or 0) > 0
    fixture_demo = (
        db.scalar(
            select(func.count())
            .select_from(ApplicationInstance)
            .where(
                ApplicationInstance.org_id == org_id,
                ApplicationInstance.display_name.contains("(demo)"),
            )
        )
        or 0
    ) > 0

    steps = [
        {
            "id": "connect",
            "label": "Connect a SaaS app",
            "done": has_connector,
            "path": "/connectors",
            "hint": "Add an integration (or run `kestrel demo up` for fixtures).",
        },
        {
            "id": "pack",
            "label": "Install a policy pack",
            "done": has_pack,
            "path": "/policies",
            "hint": "Install packs/github-posture or packs/okta-posture.",
        },
        {
            "id": "sync",
            "label": "Run a successful sync",
            "done": has_sync,
            "path": "/connectors",
            "hint": "Sync so inventory is available for policy evaluation.",
        },
        {
            "id": "triage",
            "label": "Triage open findings",
            "done": has_findings,
            "path": "/findings",
            "hint": "Open findings appear after sync + policy evaluation.",
        },
    ]
    return {
        "complete": all(s["done"] for s in steps),
        # Set per operator (kestrel.dashboard.first_run); the UI hides the
        # checklist when either this or `complete` is true.
        "dismissed": dismissed,
        "fixture_demo": fixture_demo,
        "steps": steps,
    }


def posture_overview(
    db: Session,
    org_id: uuid.UUID,
    *,
    viewer_operator_id: uuid.UUID | None = None,
    first_run_dismissed: bool = False,
) -> dict:
    """Single-request operator home payload (core SSPM metrics only).

    ``first_run_dismissed`` is the viewer's own preference, passed in so this
    stays usable with just an org id (exports, tests).
    """
    findings = _findings_rollup(db, org_id, viewer_operator_id=viewer_operator_id)
    connectors = _connector_health_rollup(db, org_id)
    return {
        "findings": findings,
        "connectors": connectors,
        "policies": {"top_failing": _top_failing_policies(db, org_id)},
        "webhooks": org_delivery_counts(db, org_id=org_id),
        "first_run": _first_run_checklist(db, org_id, connectors, findings, dismissed=first_run_dismissed),
    }
