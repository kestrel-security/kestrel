# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 -- the grant natural-key migration collapses existing duplicates.

Interleaved syncs could write the same grant twice before the unique index
existed. The migration has to dedupe such a database, not only a clean one,
or the upgrade fails on exactly the installs that need it.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from kestrel.db.models.access import Grant, GrantedVia
from kestrel.db.models.connector import ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.testing import make_connector_instance
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_scratch_db_spec = importlib.util.spec_from_file_location(
    "kestrel_tests_system_scratch_db", Path(__file__).resolve().parent / "_scratch_db.py"
)
assert _scratch_db_spec is not None
assert _scratch_db_spec.loader is not None
_scratch_db = importlib.util.module_from_spec(_scratch_db_spec)
_scratch_db_spec.loader.exec_module(_scratch_db)

PREVIOUS_REVISION = "f5a6b7c8d9e0"


def _grant(org_id, run_id, identity_id, *, last_seen: datetime, deleted: bool = False) -> Grant:
    return Grant(
        id=uuid.uuid4(),
        org_id=org_id,
        identity_id=identity_id,
        granted_via=GrantedVia.DIRECT,
        permission_level="admin",
        source_connector_run_id=run_id,
        first_seen_at=last_seen,
        last_seen_at=last_seen,
        deleted_at=last_seen if deleted else None,
    )


def test_upgrade_collapses_duplicate_grants_and_then_enforces_the_key():
    with _scratch_db.scratch_database(label="grantkey", migrate=False) as database_url:
        cfg = _scratch_db.alembic_config()
        command.upgrade(cfg, PREVIOUS_REVISION)

        now = datetime.now(UTC)
        engine = create_engine(database_url)
        try:
            with Session(engine, expire_on_commit=False) as session:
                # Raw SQL for the same reason as the run below: the model
                # carries columns later revisions added.
                org = SimpleNamespace(id=uuid.uuid4())
                session.execute(
                    text("INSERT INTO organizations (id, name, slug) VALUES (:id, 'Grant key org', :slug)"),
                    {"id": org.id, "slug": f"grant-key-{org.id.hex[:8]}"},
                )
                instance = make_connector_instance(session, org)
                # Raw SQL, not the ORM model: the model tracks head, and this
                # database is still at PREVIOUS_REVISION (no later columns).
                run_id = uuid.uuid4()
                session.execute(
                    text(
                        "INSERT INTO connector_runs (id, org_id, connector_instance_id, status, started_at,"
                        " triggered_by, object_counts, is_incremental)"
                        " VALUES (:id, :org_id, :instance_id, :status, :started_at, :trigger, '{}'::jsonb, false)"
                    ),
                    {
                        "id": run_id,
                        "org_id": org.id,
                        "instance_id": instance.id,
                        "status": ConnectorRunStatus.SUCCESS.value,
                        "started_at": now,
                        "trigger": ConnectorRunTrigger.MANUAL.value,
                    },
                )
                run = SimpleNamespace(id=run_id)
                identity = Identity(
                    id=uuid.uuid4(),
                    org_id=org.id,
                    application_instance_id=instance.application_instance_id,
                    provider_object_id="u1",
                    identity_type=IdentityType.USER,
                    source_connector_run_id=run.id,
                    raw_source={},
                )
                session.add(identity)
                session.flush()
                oldest = _grant(org.id, run.id, identity.id, last_seen=now - timedelta(days=3))
                tombstoned = _grant(org.id, run.id, identity.id, last_seen=now, deleted=True)
                live = _grant(org.id, run.id, identity.id, last_seen=now - timedelta(days=1))
                # A grant with no identity at all (a team grant): NULLs must still dedupe.
                team_a = _grant(org.id, run.id, None, last_seen=now)
                team_b = _grant(org.id, run.id, None, last_seen=now - timedelta(days=1))
                session.add_all([oldest, tombstoned, live, team_a, team_b])
                session.flush()
                session.add(
                    Event(
                        id=uuid.uuid4(),
                        org_id=org.id,
                        connector_run_id=run.id,
                        entity_type="grant",
                        entity_id=oldest.id,
                        change_type=ChangeType.CREATED,
                        field_changes=[],
                        detected_at=now,
                    )
                )
                session.commit()
                org_id, run_id, identity_id = org.id, run.id, identity.id

            command.upgrade(cfg, "head")

            with Session(engine, expire_on_commit=False) as session:
                remaining = {g.id: g for g in session.scalars(select(Grant).where(Grant.org_id == org_id)).all()}
                assert set(remaining) == {live.id, team_a.id}
                assert remaining[live.id].first_seen_at == oldest.first_seen_at
                event_entity = session.scalar(select(Event.entity_id).where(Event.org_id == org_id))
                assert event_entity == live.id

                session.add(_grant(org_id, run_id, identity_id, last_seen=now))
                with pytest.raises(IntegrityError):
                    session.flush()
                session.rollback()

            command.downgrade(cfg, PREVIOUS_REVISION)
        finally:
            engine.dispose()
