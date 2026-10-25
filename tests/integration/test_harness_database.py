# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The harness's database isolation, proved rather than assumed.

Two properties matter: each xdist worker owns a database nobody else touches,
and nothing a test writes survives it. The old suite had neither -- every test
shared the developer's `kestrel` database, and `tests/e2e` dropped its schema.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from kestrel.db.models.org import Organization
from kestrel.db.session import get_database_url, get_engine
from kestrel.testing import make_organization, savepoint_session
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url


@pytest.fixture(scope="session")
def database_registry(tmp_path_factory: pytest.TempPathFactory, worker_id: str) -> Path:
    """A directory shared by every worker in this run.

    Under xdist each worker's basetemp is `.../pytest-N/popen-gwK`, so the
    parent is the run-wide directory; in a serial run basetemp is already
    run-wide. Nothing is written inside the repository (rule 5).
    """
    base = tmp_path_factory.getbasetemp()
    root = base.parent if worker_id != "main" else base
    registry = root / "worker-databases"
    registry.mkdir(exist_ok=True)
    return registry


def _record(registry: Path, worker_id: str, database: str) -> None:
    # Atomic: another worker may be listing this directory concurrently.
    scratch = registry / f".{worker_id}.tmp"
    scratch.write_text(database)
    os.replace(scratch, registry / worker_id)


def test_each_worker_gets_its_own_database(db_session, database_registry, worker_id, worker_database_name):
    database = db_session.execute(text("SELECT current_database()")).scalar_one()
    _record(database_registry, worker_id, database)

    assert database == worker_database_name
    recorded = [path.read_text() for path in database_registry.iterdir() if not path.name.startswith(".")]
    assert len(set(recorded)) == len(recorded), f"two workers share a database: {recorded}"
    assert "kestrel" not in recorded, "a worker is pointed at the shared development database"


def test_a_second_test_sees_the_same_worker_database(db_session, database_registry, worker_id):
    """Deliberately duplicates the check above so that under `-n 4` two tests
    land on different workers and both recordings end up in the registry."""
    database = db_session.execute(text("SELECT current_database()")).scalar_one()
    _record(database_registry, worker_id, database)

    recorded = [path.read_text() for path in database_registry.iterdir() if not path.name.startswith(".")]
    assert database in recorded
    assert len(set(recorded)) == len(recorded)


def test_the_application_engine_points_at_the_worker_database(test_database_url, worker_database_name):
    """Code that reaches `kestrel.db.session.get_engine()` directly -- an
    eagerly-run Celery task, a CLI helper -- must land on the worker database
    too, not on whatever `DATABASE_URL` said before the session started."""
    assert make_url(get_database_url()).database == worker_database_name
    assert make_url(get_engine().url).database == worker_database_name


def test_application_level_commit_is_visible_and_keeps_the_outer_transaction(db_session):
    org = make_organization(db_session)
    db_session.commit()  # a route handler doing this must not end the rollback

    assert db_session.get(Organization, org.id) is not None
    assert db_session.get_bind().in_transaction(), "the outer transaction was closed by commit()"


def test_nothing_a_test_writes_survives_it(db_engine: Engine):
    """Drives the full open/commit/close cycle directly, because a fixture
    cannot assert on what is true after its own teardown."""
    with savepoint_session(db_engine) as session:
        org = make_organization(session)
        session.commit()
        org_id = org.id
        assert session.get(Organization, org_id) is not None

    with db_engine.connect() as connection:
        surviving = connection.execute(
            text("SELECT count(*) FROM organizations WHERE id = :id"), {"id": org_id}
        ).scalar_one()
    assert surviving == 0
