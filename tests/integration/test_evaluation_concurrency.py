# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- org-wide evaluation across concurrent transactions.

Everything else in this tier runs inside one rolled-back transaction, which by
construction cannot see what a second session does. This test commits for
real, through its own sessions, and deletes every row of its org on teardown.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import kestrel.db.models  # noqa: F401  (registers every table on Base.metadata)
import pytest
from kestrel.db.base import Base
from kestrel.db.models.connector import Connector, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.finding import Finding, FindingEvidence, FindingStatus
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.findings import pipeline
from kestrel.findings.pipeline import evaluate_all_enabled_policies
from kestrel.findings.toxic_combo import ensure_system_toxic_policies
from kestrel.policies.authoring import create_custom_policy
from kestrel.policies.dataload import RowCache
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

_ALWAYS_MATCH = """
POLICY_ID = "concurrency-always-matches"
TITLE = "Always matches"
SEVERITY = "high"
RESOURCE_TYPE = "identity"


def policy(resource):
    return False
"""


class _CommittedWorld:
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
                triggered_by=ConnectorRunTrigger.MANUAL,
            )
            session.add(run)
            session.flush()
            create_custom_policy(session, org_id=org.id, source_text=_ALWAYS_MATCH)
            # Created up front so the two passes below do not race to create
            # them: that is a separate symptom of the same missing lock.
            ensure_system_toxic_policies(session, org.id)
            session.commit()
        self.org_id = org.id
        self.application_instance_id = app_instance.id
        self.connector_id = instance.connector_id
        self.run_id = run.id

    def add_identity(self, session: Session) -> Identity:
        identity = Identity(
            id=uuid.uuid4(),
            org_id=self.org_id,
            application_instance_id=self.application_instance_id,
            provider_object_id=f"user-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=f"{uuid.uuid4().hex[:8]}@example.test",
            display_name="User",
            source_connector_run_id=self.run_id,
            raw_source={},
        )
        session.add(identity)
        session.flush()
        return identity

    def teardown(self) -> None:
        with self.factory() as session:
            finding_ids = select(Finding.id).where(Finding.org_id == self.org_id)
            session.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(finding_ids)))
            policy_ids = select(Policy.id).where(Policy.org_id == self.org_id)
            for table in reversed(Base.metadata.sorted_tables):
                if table.name == PolicyVersion.__tablename__:
                    session.execute(delete(PolicyVersion).where(PolicyVersion.policy_id.in_(policy_ids)))
                if "org_id" in table.c:
                    session.execute(delete(table).where(table.c.org_id == self.org_id))
            session.execute(delete(Organization).where(Organization.id == self.org_id))
            session.execute(delete(Connector).where(Connector.id == self.connector_id))
            session.commit()


@pytest.fixture
def world(db_engine: Engine) -> Iterator[_CommittedWorld]:
    built = _CommittedWorld(db_engine)
    try:
        yield built
    finally:
        built.teardown()


def test_an_overlapping_evaluation_does_not_resolve_a_finding_committed_after_it_read_rows(
    world: _CommittedWorld, monkeypatch: pytest.MonkeyPatch
):
    """Pass A reads the inventory, then pauses. Sync B commits a new identity
    and the finding it opens. Unserialised, A then reconciles against its stale
    rows and resolves B's fresh finding. With the per-org lock, B waits for A
    and evaluates current data."""
    a_has_rows = threading.Event()
    release_a = threading.Event()

    class _PausingRowCache(RowCache):
        def rows(self, from_type: str):
            loaded = super().rows(from_type)
            if threading.current_thread().name == "pass-a" and not a_has_rows.is_set():
                a_has_rows.set()
                release_a.wait(timeout=30)
            return loaded

    monkeypatch.setattr(pipeline, "RowCache", _PausingRowCache)
    errors: list[BaseException] = []
    fresh: dict[str, uuid.UUID] = {}

    def _pass_a() -> None:
        try:
            with world.factory() as session:
                evaluate_all_enabled_policies(session, world.org_id)
                session.commit()
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion
            errors.append(exc)

    def _sync_b() -> None:
        try:
            with world.factory() as session:
                fresh["identity"] = world.add_identity(session).id
                evaluate_all_enabled_policies(session, world.org_id)
                session.commit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread_a = threading.Thread(target=_pass_a, name="pass-a", daemon=True)
    thread_a.start()
    assert a_has_rows.wait(timeout=30)

    thread_b = threading.Thread(target=_sync_b, name="sync-b", daemon=True)
    thread_b.start()
    thread_b.join(timeout=3)  # unserialised, B finishes here; serialised, it waits on A
    release_a.set()
    thread_a.join(timeout=60)
    thread_b.join(timeout=60)

    assert not thread_a.is_alive()
    assert not thread_b.is_alive()
    assert errors == []
    with world.factory() as check:
        statuses = check.scalars(
            select(Finding.status).where(Finding.org_id == world.org_id, Finding.subject_id == fresh["identity"])
        ).all()
    assert statuses == [FindingStatus.OPEN]
