# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- sync behaviour that only shows up across concurrent transactions.

Everything else in this tier runs inside one rolled-back transaction, which by
construction cannot see what a second session does. These tests commit for
real, through their own sessions, and delete every row of their org on
teardown.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import kestrel.db.models  # noqa: F401  (registers every table on Base.metadata)
import pytest
from kestrel.connectors.sdk.base import HealthCheckResult, NormalizedObject, RawObject
from kestrel.db.base import Base
from kestrel.db.models.connector import Connector, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.identity_link import IdentityLink
from kestrel.db.models.org import Organization
from kestrel.sync.pipeline import refresh_identity_correlation
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker


class CommittedWorld:
    def __init__(self, engine: Engine) -> None:
        self.factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with self.factory() as session:
            org = make_organization(session)
            app_instance = make_application_instance(session, org)
            instance = make_connector_instance(session, org, application_instance=app_instance)
            run = ConnectorRun(
                id=uuid.uuid4(),
                org_id=org.id,
                connector_instance_id=instance.id,
                status=ConnectorRunStatus.SUCCESS,
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                triggered_by=ConnectorRunTrigger.MANUAL,
            )
            session.add(run)
            session.flush()
            session.commit()
        self.org_id = org.id
        self.application_instance_id = app_instance.id
        self.connector_instance_id = instance.id
        self.connector_id = instance.connector_id
        self.seed_run_id = run.id

    def session(self) -> Session:
        return self.factory()

    def add_identities(self, count: int) -> None:
        with self.factory() as session:
            for index in range(count):
                session.add(
                    Identity(
                        id=uuid.uuid4(),
                        org_id=self.org_id,
                        application_instance_id=self.application_instance_id,
                        provider_object_id=f"user-{index}",
                        identity_type=IdentityType.USER,
                        email=f"user{index}@example.test",
                        display_name=f"User {index}",
                        source_connector_run_id=self.seed_run_id,
                        raw_source={},
                    )
                )
            session.commit()

    def teardown(self) -> None:
        with self.factory() as session:
            for table in reversed(Base.metadata.sorted_tables):
                if "org_id" in table.c:
                    session.execute(delete(table).where(table.c.org_id == self.org_id))
                    continue
                # Child tables without their own org_id (policy_versions, ...):
                # reach the org through the parent they reference.
                for fk in table.foreign_keys:
                    parent = fk.column.table
                    if "org_id" in parent.c:
                        owned = select(fk.column).where(parent.c.org_id == self.org_id)
                        session.execute(delete(table).where(fk.parent.in_(owned)))
            session.execute(delete(Organization).where(Organization.id == self.org_id))
            session.execute(delete(Connector).where(Connector.id == self.connector_id))
            session.commit()


@pytest.fixture
def committed_world(db_engine: Engine) -> Iterator[CommittedWorld]:
    world = CommittedWorld(db_engine)
    try:
        yield world
    finally:
        world.teardown()


def _in_thread(target) -> tuple[threading.Thread, list[BaseException]]:
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            target()
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion
            errors.append(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread, errors


def test_concurrent_correlation_rebuilds_in_one_org_do_not_collide(committed_world: CommittedWorld):
    committed_world.add_identities(3)
    org_id = committed_world.org_id

    session_a = committed_world.session()
    refresh_identity_correlation(session_a, org_id=org_id)  # uncommitted, like a sync still evaluating

    def _second_sync() -> None:
        with committed_world.session() as session_b:
            refresh_identity_correlation(session_b, org_id=org_id)
            session_b.commit()

    thread, errors = _in_thread(_second_sync)
    time.sleep(0.5)  # let B reach the point where it waits on A
    session_a.commit()
    session_a.close()
    thread.join(timeout=30)

    assert not thread.is_alive()
    assert errors == []
    with committed_world.session() as check:
        count = check.scalar(select(func.count()).select_from(IdentityLink).where(IdentityLink.org_id == org_id))
    assert count == 3


# --------------------------------------------------------------------------
# Run lifecycle: worker task and `kestrel sync --no-async`.
# --------------------------------------------------------------------------


class _Collector:
    def __init__(self, behaviour) -> None:
        self._behaviour = behaviour
        self.skipped_object_types: dict[str, str] = {}

    def discover(self) -> list[str]:
        return ["identity"]

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterator[RawObject]:
        self._behaviour()
        return iter(())

    def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(healthy=True, message="ok")


class _Normalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        return []


class BehaviourConnector:
    """Collects nothing; ``behaviour`` runs inside collection (raise, block)."""

    manifest = None

    def __init__(self, behaviour=lambda: None, skipped_object_types: dict[str, str] | None = None) -> None:
        self._behaviour = behaviour
        self._skipped = dict(skipped_object_types or {})

    def configure(self, config: dict[str, Any]) -> None:
        pass

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Any:
        raise NotImplementedError

    def build_collector(self, transport: Any) -> _Collector:
        collector = _Collector(self._behaviour)
        collector.skipped_object_types = dict(self._skipped)
        return collector

    def build_normalizer(self) -> _Normalizer:
        return _Normalizer()


@pytest.fixture
def worker_task(committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch):
    """Runs the real Celery task body against the committed world with a given connector."""
    import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
    from kestrel.sync.lock import InMemorySyncLock
    from kestrel_worker.tasks import sync as sync_task

    monkeypatch.setattr(sync_task, "get_sessionmaker", lambda: committed_world.factory)
    monkeypatch.setattr(sync_task, "get_sync_lock", lambda: InMemorySyncLock())
    monkeypatch.setattr(sync_task, "load_fixture_transport_builder", lambda name: lambda: object())
    monkeypatch.setattr(sync_task.deliver_webhook, "delay", lambda **kwargs: None)

    def _run(connector: BehaviourConnector) -> str:
        monkeypatch.setattr(sync_task, "load_connector", lambda name: connector)
        return sync_task.run_connector_sync.run(
            connector_instance_id=str(committed_world.connector_instance_id), connector_name="scripted", config={}
        )

    return _run


def _runs(world: CommittedWorld) -> list[ConnectorRun]:
    with world.session() as session:
        return list(
            session.scalars(
                select(ConnectorRun)
                .where(ConnectorRun.connector_instance_id == world.connector_instance_id)
                .order_by(ConnectorRun.started_at)
            ).all()
        )


def test_soft_time_limit_records_the_timed_out_run_and_leaves_the_previous_one(committed_world, worker_task):
    from celery.exceptions import SoftTimeLimitExceeded

    def _hang() -> None:
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        worker_task(BehaviourConnector(_hang))

    previous, current = _runs(committed_world)
    assert previous.id == committed_world.seed_run_id
    assert previous.status is ConnectorRunStatus.SUCCESS
    assert previous.error_summary is None
    assert current.status is ConnectorRunStatus.FAILED
    assert "timed out" in (current.error_summary or "")


def test_a_failure_in_post_sync_evaluation_keeps_the_sync_and_says_so(committed_world, worker_task, monkeypatch):
    import kestrel.sync.execute as execute

    def _broken_evaluation(*args, **kwargs):
        raise RuntimeError("policy engine exploded")

    monkeypatch.setattr(execute, "evaluate_all_enabled_policies", _broken_evaluation)

    with pytest.raises(RuntimeError):
        worker_task(BehaviourConnector())

    current = _runs(committed_world)[-1]
    assert current.id != committed_world.seed_run_id
    assert current.status is ConnectorRunStatus.SUCCESS
    assert "policy evaluation failed" in (current.error_summary or "")
    assert "policy engine exploded" in (current.error_summary or "")
    assert current.evaluation_pending is True


def test_a_successful_evaluation_settles_the_run(committed_world, worker_task):
    worker_task(BehaviourConnector())

    assert _runs(committed_world)[-1].evaluation_pending is False


def test_the_run_reads_finished_while_policies_are_still_evaluating(committed_world, worker_task, monkeypatch):
    import kestrel.sync.execute as execute

    in_evaluation = threading.Event()
    release = threading.Event()

    def _slow_evaluation(*args, **kwargs):
        in_evaluation.set()
        release.wait(timeout=30)

    monkeypatch.setattr(execute, "evaluate_all_enabled_policies", _slow_evaluation)
    thread, errors = _in_thread(lambda: worker_task(BehaviourConnector()))
    try:
        assert in_evaluation.wait(timeout=30)
        assert _runs(committed_world)[-1].status is ConnectorRunStatus.SUCCESS
    finally:
        release.set()
        thread.join(timeout=30)
    assert errors == []


def test_the_running_run_is_visible_to_other_sessions_while_the_sync_is_in_progress(committed_world, worker_task):
    from kestrel.sync.lock import active_run_for

    in_collector = threading.Event()
    release = threading.Event()

    def _pause() -> None:
        in_collector.set()
        release.wait(timeout=30)

    thread, errors = _in_thread(lambda: worker_task(BehaviourConnector(_pause)))
    try:
        assert in_collector.wait(timeout=30)
        with committed_world.session() as observer:
            active = active_run_for(observer, connector_instance_id=committed_world.connector_instance_id)
        assert active is not None
    finally:
        release.set()
        thread.join(timeout=30)
    assert errors == []
    assert _runs(committed_world)[-1].status is ConnectorRunStatus.SUCCESS


def test_cli_sync_records_a_failed_run(committed_world, monkeypatch):
    from kestrel.cli import sync as cli_sync

    def _boom() -> None:
        raise RuntimeError("provider said no")

    monkeypatch.setattr(cli_sync, "get_sessionmaker", lambda: committed_world.factory)
    monkeypatch.setattr(cli_sync, "load_connector", lambda name: BehaviourConnector(_boom))
    monkeypatch.setattr(cli_sync, "load_fixture_transport_builder", lambda name: lambda: object())

    with pytest.raises(RuntimeError):
        cli_sync.sync(connector_instance_id=str(committed_world.connector_instance_id), connector_name="x", no_async=True)

    current = _runs(committed_world)[-1]
    assert current.id != committed_world.seed_run_id
    assert current.status is ConnectorRunStatus.FAILED
    assert "provider said no" in (current.error_summary or "")


def test_cli_sync_evaluates_a_partial_run(committed_world, monkeypatch):
    import kestrel.sync.execute as execute
    from kestrel.cli import sync as cli_sync

    evaluated: list[uuid.UUID] = []

    def _record(session, *, org_id, connector_run_id, **kwargs) -> None:
        evaluated.append(connector_run_id)

    monkeypatch.setattr(execute, "evaluate_all_enabled_policies", _record)
    monkeypatch.setattr(cli_sync, "get_sessionmaker", lambda: committed_world.factory)
    monkeypatch.setattr(
        cli_sync,
        "load_connector",
        lambda name: BehaviourConnector(skipped_object_types={"audit_log": "plan does not include it"}),
    )
    monkeypatch.setattr(cli_sync, "load_fixture_transport_builder", lambda name: lambda: object())

    cli_sync.sync(connector_instance_id=str(committed_world.connector_instance_id), connector_name="x", no_async=True)

    current = _runs(committed_world)[-1]
    assert current.status is ConnectorRunStatus.PARTIAL_FAILURE
    assert evaluated == [current.id]


def test_cli_sync_refuses_a_demo_instance(committed_world, monkeypatch):
    import typer
    from kestrel.cli import sync as cli_sync
    from kestrel.db.models.connector import ConnectorInstance, SyncMode
    from kestrel.demo import DEMO_CONFIG_FLAG

    with committed_world.session() as session:
        instance = session.get(ConnectorInstance, committed_world.connector_instance_id)
        instance.sync_mode = SyncMode.FIXTURES
        instance.config = {**(instance.config or {}), DEMO_CONFIG_FLAG: True}
        session.commit()
    runs_before = len(_runs(committed_world))
    monkeypatch.setattr(cli_sync, "get_sessionmaker", lambda: committed_world.factory)
    monkeypatch.setattr(cli_sync, "load_connector", lambda name: BehaviourConnector())

    with pytest.raises(typer.Exit):
        cli_sync.sync(connector_instance_id=str(committed_world.connector_instance_id), connector_name="x", no_async=True)

    assert len(_runs(committed_world)) == runs_before


# -- Lock TTL versus task time limits -----------------------------------------


def test_the_lock_ttl_never_falls_below_the_hard_time_limit(monkeypatch: pytest.MonkeyPatch):
    """A TTL shorter than the task can run let the lock expire mid-run: a second
    worker started the same instance and the live run was marked FAILED as
    stale. The TTL floors at the hard limit plus headroom, whatever is set."""
    from kestrel.sync.lock import lock_ttl_seconds

    monkeypatch.setenv("KESTREL_SYNC_LOCK_TTL_SECONDS", "300")
    monkeypatch.setenv("KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS", "1500")
    monkeypatch.setenv("KESTREL_SYNC_TIME_LIMIT_SECONDS", "1800")
    assert lock_ttl_seconds() == 1800 + 60

    # The hard limit itself floors at soft + 60, exactly as the worker derives it.
    monkeypatch.setenv("KESTREL_SYNC_SOFT_TIME_LIMIT_SECONDS", "3000")
    assert lock_ttl_seconds() == 3000 + 60 + 60

    # A TTL the operator set *above* the limits is honoured as-is.
    monkeypatch.setenv("KESTREL_SYNC_LOCK_TTL_SECONDS", "7200")
    assert lock_ttl_seconds() == 7200
