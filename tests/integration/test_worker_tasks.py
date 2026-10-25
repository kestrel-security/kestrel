# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the worker's periodic and on-demand tasks against a real
session: each task opens its own session through ``get_sessionmaker``, so the
test points that at the test's savepoint session (with ``close`` made a no-op,
since the fixture owns the session's lifetime) and captures ``.delay`` calls
instead of needing a broker."""

from __future__ import annotations

# The Celery app registers every task module on import; importing a task
# module before it re-enters that registration half-initialized.
import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from kestrel.dashboard import boards as boards_svc
from kestrel.dashboard import schedules as schedules_svc
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.dashboard import DashboardSchedule
from kestrel.db.models.finding import FindingStatus
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.db.models.webhook import FINDING_OPENED, WebhookDelivery
from kestrel.findings.mute import mute_finding_for_days
from kestrel.notifications.email_transport import EmailResult
from kestrel.testing import make_connector, make_connector_instance, make_operator, make_organization
from kestrel_worker.tasks import dashboard_schedules as dashboard_task
from kestrel_worker.tasks import evaluate as evaluate_task
from kestrel_worker.tasks import finding_lifecycle as lifecycle_task
from kestrel_worker.tasks import posture_trend as posture_task
from kestrel_worker.tasks import schedule as schedule_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.integration.finding_world import FindingWorld


class _BorrowedSession:
    """The test's session, lent to a task that will try to close it."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def close(self) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


@dataclass
class _Delays:
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


@pytest.fixture
def lend_session(db_session: Session, monkeypatch: pytest.MonkeyPatch):
    def lend(*modules: Any) -> None:
        for module in modules:
            monkeypatch.setattr(module, "get_sessionmaker", lambda: lambda: _BorrowedSession(db_session))

    return lend


def _capture(monkeypatch: pytest.MonkeyPatch, task: Any) -> _Delays:
    delays = _Delays()
    monkeypatch.setattr(task, "delay", delays)
    return delays


# --- evaluate_policies -------------------------------------------------------


def test_evaluate_task_opens_findings_and_enqueues_their_webhooks(
    db_session: Session, lend_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy()
    lend_session(evaluate_task)
    delays = _capture(monkeypatch, evaluate_task.deliver_webhook)

    evaluations = evaluate_task.evaluate_policies.run(org_id=str(world.org.id), connector_run_id=str(world.run.id))

    assert evaluations >= 1
    assert len(world.findings(policy)) == 2
    opened = set(
        db_session.scalars(
            select(WebhookDelivery.id).where(
                WebhookDelivery.org_id == world.org.id, WebhookDelivery.event_type == FINDING_OPENED
            )
        ).all()
    )
    assert len(opened) == 2
    assert {uuid.UUID(call["delivery_id"]) for call in delays.calls} == opened


# --- reopen_expired_finding_deferrals ----------------------------------------


def test_reopen_task_reopens_an_expired_mute_and_announces_it_after_commit(
    db_session: Session, lend_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy()
    world.evaluate()
    expired, live = world.findings(policy)
    mute_finding_for_days(expired, days=1)
    mute_finding_for_days(live, days=1)
    expired.muted_until = datetime.now(UTC) - timedelta(minutes=1)
    db_session.flush()
    before = set(db_session.scalars(select(WebhookDelivery.id).where(WebhookDelivery.org_id == world.org.id)).all())
    lend_session(lifecycle_task)
    delays = _capture(monkeypatch, lifecycle_task.deliver_webhook)

    reopened = lifecycle_task.reopen_expired_finding_deferrals.run()

    assert reopened >= 1
    assert expired.status == FindingStatus.OPEN
    assert live.status == FindingStatus.MUTED
    after = set(db_session.scalars(select(WebhookDelivery.id).where(WebhookDelivery.org_id == world.org.id)).all())
    new = after - before
    assert len(new) == 1
    assert {uuid.UUID(call["delivery_id"]) for call in delays.calls} >= new


# --- capture_daily_posture_snapshots -----------------------------------------


def test_posture_task_snapshots_every_org(db_session: Session, lend_session) -> None:
    first = make_organization(db_session)
    second = make_organization(db_session)
    lend_session(posture_task)

    captured = posture_task.capture_daily_posture_snapshots.run()

    assert captured >= 2
    for org in (first, second):
        rows = db_session.scalars(select(PostureTrendSnapshot).where(PostureTrendSnapshot.org_id == org.id)).all()
        assert len(rows) == 1


# --- dispatch_dashboard_schedules --------------------------------------------


@dataclass
class _RecordingTransport:
    sent: list[dict[str, Any]] = field(default_factory=list)

    def send(self, **kwargs: Any) -> EmailResult:
        self.sent.append(kwargs)
        return EmailResult(delivered=True, backend="smtp", detail=None)


def _dashboard_schedule(db_session: Session, *, cron: str, last_run_at: datetime | None) -> DashboardSchedule:
    org = make_organization(db_session)
    admin = make_operator(db_session, org, role=OperatorRole.ADMIN)
    board = boards_svc.create_dashboard(db_session, org_id=org.id, operator=admin, name="Scheduled board")
    created = schedules_svc.create_schedule(
        db_session,
        org_id=org.id,
        dashboard_id=board["id"],
        operator=admin,
        cron=cron,
        fmt="json",
        recipient_operator_ids=[str(admin.id)],
    )
    schedule = db_session.get(DashboardSchedule, created["id"])
    assert schedule is not None
    schedule.last_run_at = last_run_at
    db_session.flush()
    return schedule


def test_dashboard_task_runs_overdue_schedules_and_leaves_others(
    db_session: Session, lend_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = _RecordingTransport()
    monkeypatch.setattr(schedules_svc, "email_transport_for_org", lambda _db, _org_id: transport)
    # Last ran years ago on a daily cron: due whenever the test runs.
    overdue = _dashboard_schedule(db_session, cron="0 9 * * *", last_run_at=datetime(2020, 1, 1, tzinfo=UTC))
    # Ran "now" on a yearly cron: not due again for a year.
    recent_run = datetime.now(UTC)
    fresh = _dashboard_schedule(db_session, cron="0 0 1 1 *", last_run_at=recent_run)
    lend_session(dashboard_task)

    ran = dashboard_task.dispatch_dashboard_schedules.run()

    assert ran >= 1
    assert overdue.last_status == "success"
    assert overdue.last_run_at is not None
    assert overdue.last_run_at > datetime(2020, 1, 1, tzinfo=UTC)
    assert fresh.last_run_at == recent_run
    assert fresh.last_status is None
    assert len([m for m in transport.sent if "Scheduled board" in m["subject"]]) == ran


# --- dispatch_scheduled_syncs / dispatch_event_syncs -------------------------


@pytest.fixture
def ledger(monkeypatch: pytest.MonkeyPatch) -> schedule_task.InMemoryDispatchLedger:
    fresh = schedule_task.InMemoryDispatchLedger()
    monkeypatch.setattr(schedule_task, "get_dispatch_ledger", lambda: fresh)
    return fresh


def _running(db_session: Session, instance) -> None:
    db_session.add(
        ConnectorRun(
            id=uuid.uuid4(),
            org_id=instance.org_id,
            connector_instance_id=instance.id,
            status=ConnectorRunStatus.RUNNING,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.SCHEDULE,
        )
    )
    db_session.flush()


def _calls_for(delays: _Delays, instance) -> list[dict[str, Any]]:
    return [c for c in delays.calls if c["connector_instance_id"] == str(instance.id)]


def test_scheduled_sync_dispatch_enqueues_due_instances_once_and_skips_bad_or_busy_ones(
    db_session: Session, lend_session, ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    org = make_organization(db_session)
    connector = make_connector(db_session)
    due = make_connector_instance(db_session, org, connector=connector, schedule_cron="* * * * *", config={"k": "v"})
    invalid = make_connector_instance(db_session, org, connector=connector, schedule_cron="not a cron")
    busy = make_connector_instance(db_session, org, connector=connector, schedule_cron="* * * * *")
    manual = make_connector_instance(db_session, org, connector=connector, schedule_cron=None)
    _running(db_session, busy)
    lend_session(schedule_task)
    delays = _capture(monkeypatch, schedule_task.run_connector_sync)

    schedule_task.dispatch_scheduled_syncs.run()

    assert _calls_for(delays, due) == [
        {
            "connector_instance_id": str(due.id),
            "connector_name": connector.name,
            "config": {"k": "v"},
            "triggered_by": "schedule",
        }
    ]
    for skipped in (invalid, busy, manual):
        assert _calls_for(delays, skipped) == []
    # The busy instance's fire was claimed and consumed, not deferred.
    assert ledger.last_fire(str(busy.id)) is not None
    assert ledger.last_fire(str(due.id)) is not None
    assert ledger.last_fire(str(invalid.id)) is None


def test_event_sync_dispatch_polls_only_scheduled_instances_with_incremental_types(
    db_session: Session, lend_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    org = make_organization(db_session)
    incremental = make_connector(
        db_session,
        manifest={
            "object_types": [
                {"name": "audit_event", "supports_incremental": True},
                {"name": "user", "supports_incremental": False},
            ]
        },
    )
    full_only = make_connector(db_session, manifest={"object_types": [{"name": "user"}]})
    eligible = make_connector_instance(db_session, org, connector=incremental, schedule_cron="0 * * * *")
    busy = make_connector_instance(db_session, org, connector=incremental, schedule_cron="0 * * * *")
    unscheduled = make_connector_instance(db_session, org, connector=incremental, schedule_cron=None)
    no_incremental = make_connector_instance(db_session, org, connector=full_only, schedule_cron="0 * * * *")
    _running(db_session, busy)
    lend_session(schedule_task)
    delays = _capture(monkeypatch, schedule_task.run_connector_sync)

    schedule_task.dispatch_event_syncs.run()

    assert _calls_for(delays, eligible) == [
        {
            "connector_instance_id": str(eligible.id),
            "connector_name": incremental.name,
            "config": {},
            "triggered_by": "schedule",
            "object_types": ["audit_event"],
        }
    ]
    for skipped in (busy, unscheduled, no_incremental):
        assert _calls_for(delays, skipped) == []
