# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 may do destructive things to its database, and only its own.

This is the property that makes the system tier safe to have at all. The old
`tests/e2e/test_vertical_slice.py` ran `DROP SCHEMA public CASCADE` against the
shared development database and overwrote `REPO_ROOT/.env`; per-worker
databases are why an equivalent test is now harmless.
"""

from __future__ import annotations

from kestrel.testing import savepoint_session
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url


def test_destructive_ddl_stays_inside_this_workers_database(db_engine: Engine, worker_database_name: str):
    assert make_url(db_engine.url).database == worker_database_name

    with db_engine.begin() as connection:
        connection.execute(text("CREATE TABLE harness_ddl_probe (id integer primary key)"))
        assert connection.execute(text("SELECT to_regclass('harness_ddl_probe')")).scalar_one() is not None
        connection.execute(text("DROP TABLE harness_ddl_probe"))

    with db_engine.connect() as connection:
        assert connection.execute(text("SELECT to_regclass('harness_ddl_probe')")).scalar_one() is None


def test_the_migrated_schema_is_present(db_engine: Engine):
    """The worker database is a clone of the template, so it carries the
    migrations without any test having to run alembic."""
    with savepoint_session(db_engine) as session:
        revisions = session.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        assert len(revisions) == 1
        assert session.execute(text("SELECT count(*) FROM organizations")).scalar_one() >= 0
