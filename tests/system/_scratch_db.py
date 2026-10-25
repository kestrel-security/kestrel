# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared helper for tests/system/ files that need a throwaway Postgres
database of their own -- never the per-worker database
``tests/system/conftest.py`` points every other test at.

Not a ``test_*.py`` module (pytest's default ``python_files`` pattern skips
it), so it is a plain importable helper, not a source of collected tests.

Two callers need this: the CLI e2e test (``kestrel init`` commits through
its own session, outside any test's rolled-back transaction) and the
migration replay test (upgrade/downgrade must run against a database this
test owns outright).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic.config import Config
from kestrel.db.session import get_database_url, reset_engine
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

REPO_ROOT = Path(__file__).resolve().parents[2]
DISPOSABLE_PREFIX = "kestrel_test_"


def alembic_config() -> Config:
    """An Alembic Config with an absolute script_location -- correct
    regardless of the caller's current working directory."""
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    return cfg


def _maintenance_engine(base_url: URL):
    return create_engine(base_url.set(database="postgres"), isolation_level="AUTOCOMMIT", poolclass=NullPool)


def _terminate_and_drop(base_url: URL, name: str) -> None:
    engine = _maintenance_engine(base_url)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    finally:
        engine.dispose()


@contextmanager
def scratch_database(*, label: str, migrate: bool = True) -> Iterator[str]:
    """Creates ``kestrel_test_<label>_<random>``, points ``DATABASE_URL`` at
    it (resetting kestrel's memoized Engine), optionally applies every
    migration, yields the URL, then drops the database and restores the
    previous ``DATABASE_URL``.
    """
    base_url = make_url(get_database_url())
    name = f"{DISPOSABLE_PREFIX}{label}_{uuid.uuid4().hex[:12]}"
    assert name.startswith(DISPOSABLE_PREFIX)

    engine = _maintenance_engine(base_url)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        engine.dispose()

    target_url = base_url.set(database=name).render_as_string(hide_password=False)
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = target_url
    reset_engine()
    try:
        if migrate:
            from alembic import command

            command.upgrade(alembic_config(), "head")
        yield target_url
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        reset_engine()
        _terminate_and_drop(base_url, name)
