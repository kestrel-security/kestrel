# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard email schedules."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.dashboard.boards import get_dashboard
from kestrel.dashboard.export import export_dashboard
from kestrel.db.models.dashboard import DashboardSchedule, DashboardScheduleFormat
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.notifications.smtp_settings import email_transport_for_org

logger = logging.getLogger(__name__)

MAX_SCHEDULES_PER_ORG = 20
MAX_RECIPIENTS = 20


def _schedule_to_dict(s: DashboardSchedule) -> dict[str, Any]:
    return {
        "id": str(s.id),
        "dashboard_id": str(s.dashboard_id),
        "cron": s.cron,
        "timezone": s.timezone,
        "format": s.format.value,
        "recipient_operator_ids": list(s.recipient_operator_ids or []),
        "enabled": s.enabled,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "last_status": s.last_status,
        "last_error": s.last_error,
        "created_by_operator_id": str(s.created_by_operator_id) if s.created_by_operator_id else None,
    }


def create_schedule(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    operator: Operator,
    cron: str,
    timezone: str = "UTC",
    fmt: str = "pdf",
    recipient_operator_ids: list[str],
) -> dict[str, Any]:
    if operator.role != OperatorRole.ADMIN:
        raise PermissionError("only admins can create dashboard schedules")
    get_dashboard(db, org_id=org_id, dashboard_id=dashboard_id, operator=operator)
    existing = db.scalars(select(DashboardSchedule).where(DashboardSchedule.org_id == org_id)).all()
    if len(existing) >= MAX_SCHEDULES_PER_ORG:
        raise ValueError(f"max {MAX_SCHEDULES_PER_ORG} schedules per org")
    if not recipient_operator_ids:
        raise ValueError("at least one recipient required")
    if len(recipient_operator_ids) > MAX_RECIPIENTS:
        raise ValueError(f"max {MAX_RECIPIENTS} recipients")
    # Validate cron + timezone
    try:
        ZoneInfo(timezone)
    except Exception as exc:
        raise ValueError(f"invalid timezone: {timezone}") from exc
    try:
        croniter(cron, datetime.now(UTC))
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid cron: {cron}") from exc

    # Recipients must be org operators
    recip_uuids = [uuid.UUID(r) for r in recipient_operator_ids]
    ops = list(db.scalars(select(Operator).where(Operator.org_id == org_id, Operator.id.in_(recip_uuids))).all())
    if len(ops) != len(set(recip_uuids)):
        raise ValueError("all recipients must be operators in this org")

    row = DashboardSchedule(
        org_id=org_id,
        dashboard_id=dashboard_id,
        cron=cron,
        timezone=timezone,
        format=DashboardScheduleFormat(fmt),
        recipient_operator_ids=[str(u) for u in recip_uuids],
        enabled=True,
        created_by_operator_id=operator.id,
    )
    db.add(row)
    db.flush()
    return _schedule_to_dict(row)


def update_schedule(
    db: Session,
    *,
    org_id: uuid.UUID,
    dashboard_id: uuid.UUID,
    schedule_id: uuid.UUID,
    operator: Operator,
    **fields: Any,
) -> dict[str, Any]:
    if operator.role != OperatorRole.ADMIN:
        raise PermissionError("only admins can update schedules")
    row = db.scalars(
        select(DashboardSchedule).where(
            DashboardSchedule.id == schedule_id,
            DashboardSchedule.dashboard_id == dashboard_id,
            DashboardSchedule.org_id == org_id,
        )
    ).first()
    if row is None:
        raise LookupError("schedule not found")
    if "cron" in fields and fields["cron"] is not None:
        croniter(fields["cron"], datetime.now(UTC))
        row.cron = fields["cron"]
    if "timezone" in fields and fields["timezone"] is not None:
        try:
            ZoneInfo(fields["timezone"])
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"invalid timezone: {fields['timezone']}") from exc
        row.timezone = fields["timezone"]
    if "format" in fields and fields["format"] is not None:
        row.format = DashboardScheduleFormat(fields["format"])
    if "enabled" in fields and fields["enabled"] is not None:
        row.enabled = bool(fields["enabled"])
    if "recipient_operator_ids" in fields and fields["recipient_operator_ids"] is not None:
        ids = [uuid.UUID(r) for r in fields["recipient_operator_ids"]]
        if len(ids) > MAX_RECIPIENTS or not ids:
            raise ValueError("invalid recipients")
        ops = list(db.scalars(select(Operator).where(Operator.org_id == org_id, Operator.id.in_(ids))).all())
        if len(ops) != len(set(ids)):
            raise ValueError("all recipients must be operators in this org")
        row.recipient_operator_ids = [str(u) for u in ids]
    db.add(row)
    db.flush()
    return _schedule_to_dict(row)


def delete_schedule(
    db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID, schedule_id: uuid.UUID, operator: Operator
) -> None:
    if operator.role != OperatorRole.ADMIN:
        raise PermissionError("only admins can delete schedules")
    row = db.scalars(
        select(DashboardSchedule).where(
            DashboardSchedule.id == schedule_id,
            DashboardSchedule.dashboard_id == dashboard_id,
            DashboardSchedule.org_id == org_id,
        )
    ).first()
    if row is None:
        raise LookupError("schedule not found")
    db.delete(row)
    db.flush()


def list_schedules_for_dashboard(db: Session, *, org_id: uuid.UUID, dashboard_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(DashboardSchedule).where(
            DashboardSchedule.org_id == org_id,
            DashboardSchedule.dashboard_id == dashboard_id,
        )
    ).all()
    return [_schedule_to_dict(r) for r in rows]


def is_schedule_due(schedule: DashboardSchedule, now: datetime | None = None) -> bool:
    clock = now or datetime.now(UTC)
    try:
        tz = ZoneInfo(schedule.timezone or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        tz = ZoneInfo("UTC")
    local_now = clock.astimezone(tz)
    base = schedule.last_run_at.astimezone(tz) if schedule.last_run_at else local_now
    try:
        itr = croniter(schedule.cron, base)
        next_fire = itr.get_next(datetime)
    except (ValueError, KeyError, TypeError):
        return False
    # Due if next fire from last_run is <= now (or never run and next from now-1m would have fired)
    if schedule.last_run_at is None:
        itr2 = croniter(schedule.cron, local_now)
        prev = itr2.get_prev(datetime)
        return prev <= local_now and (local_now - prev).total_seconds() < 90
    return next_fire <= local_now


def run_schedule(db: Session, schedule: DashboardSchedule) -> dict[str, Any]:
    """Render export and email recipients. Updates last_run_* on the schedule."""
    recipients = list(
        db.scalars(
            select(Operator).where(
                Operator.org_id == schedule.org_id,
                Operator.id.in_([uuid.UUID(x) for x in (schedule.recipient_operator_ids or [])]),
                Operator.is_active.is_(True),
            )
        ).all()
    )
    if not recipients:
        schedule.last_run_at = datetime.now(UTC)
        schedule.last_status = "failed"
        schedule.last_error = "no active recipients"
        db.add(schedule)
        db.flush()
        return {"ok": False, "error": "no active recipients"}

    actor = recipients[0]
    try:
        payload, _media, filename = export_dashboard(
            db,
            org_id=schedule.org_id,
            dashboard_id=schedule.dashboard_id,
            operator=actor,
            fmt=schedule.format.value,
        )
    except Exception as exc:  # deliberately broad: any export failure is recorded on the schedule, not raised
        logger.warning("dashboard_schedule_export_failed", extra={"schedule_id": str(schedule.id)}, exc_info=True)
        schedule.last_run_at = datetime.now(UTC)
        schedule.last_status = "failed"
        schedule.last_error = str(exc)[:500]
        db.add(schedule)
        db.flush()
        return {"ok": False, "error": str(exc)}

    board = get_dashboard(db, org_id=schedule.org_id, dashboard_id=schedule.dashboard_id, operator=actor)
    transport = email_transport_for_org(db, schedule.org_id)
    emails = [op.email for op in recipients if op.email]
    mime = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
    }.get(schedule.format.value, "application/octet-stream")
    # One email per run. An HTML export also renders inline as the body, with
    # the file still attached for clients that strip HTML.
    result = transport.send(
        to=emails,
        subject=f"Kestrel dashboard: {board.get('name')}",
        text_body=f"Attached: scheduled export of dashboard '{board.get('name')}'.",
        html_body=payload.decode("utf-8", errors="replace") if schedule.format.value == "html" else None,
        attachments=[(filename, payload, mime)],
    )

    schedule.last_run_at = datetime.now(UTC)
    if result.delivered:
        schedule.last_status = "success"
        schedule.last_error = None
    else:
        schedule.last_status = "stub" if result.backend == "stub" else "failed"
        schedule.last_error = result.detail
    db.add(schedule)
    db.flush()
    return {"ok": result.delivered or result.backend == "stub", "backend": result.backend, "detail": result.detail}


def dispatch_due_schedules(db: Session, now: datetime | None = None) -> int:
    """Find enabled schedules that are due and run them. Returns count attempted."""
    clock = now or datetime.now(UTC)
    rows = list(db.scalars(select(DashboardSchedule).where(DashboardSchedule.enabled.is_(True))).all())
    ran = 0
    for sched in rows:
        if not is_schedule_due(sched, clock):
            continue
        try:
            run_schedule(db, sched)
            ran += 1
        except Exception:
            logger.exception("dashboard_schedule_failed", extra={"schedule_id": str(sched.id)})
            sched.last_run_at = clock
            sched.last_status = "failed"
            sched.last_error = "uncaught error"
            db.add(sched)
    db.commit()
    return ran
