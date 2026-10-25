# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Transaction scoping for tests that run against a real database.

The problem this solves: application code under test (an API route handler, a
sync step) legitimately calls ``session.commit()``. A test that merely opened a
transaction and rolled it back at the end would find that the first
``commit()`` ended the very transaction it was relying on, leaving rows behind
in a database other tests share.

The fix is the standard SQLAlchemy "join an external transaction" recipe: run
the session inside a SAVEPOINT and start a fresh one every time the current one
ends, so application-level commits only ever release a savepoint while the real
outer transaction stays open and is rolled back at teardown.

Lives in ``kestrel.testing`` rather than in a ``conftest.py`` so that connector
authors building against the SDK get the same isolation without copying it, and
so Kestrel's own harness self-tests can exercise the full open/commit/rollback
cycle directly instead of only through a fixture.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker


@contextmanager
def savepoint_session(engine: Engine) -> Iterator[Session]:
    """Yield a ``Session`` whose writes are always rolled back on exit.

    ``expire_on_commit`` / ``autoflush`` match ``kestrel.db.session``'s
    production sessionmaker, so code behaves under test the way it behaves in
    the API process.

    Uses SQLAlchemy 2.0's ``join_transaction_mode="create_savepoint"``: the
    Session opens a SAVEPOINT against the externally-begun transaction and
    manages its own nesting from there. Both ``commit()`` and ``rollback()`` in
    application code resolve against that savepoint, leaving the outer
    transaction intact for teardown to roll back.

    The older recipe for this -- ``begin_nested()`` plus an
    ``after_transaction_end`` listener that restarts the savepoint -- handles
    ``commit()`` but not ``rollback()``: a router rolling back on an error path
    unwound past the savepoint and deassociated the outer transaction, so
    teardown warned ``transaction already deassociated from connection`` and the
    rollback guarantee silently degraded to "the connection closed and discarded
    the writes". Two separate test suites hit that independently.
    """
    connection = engine.connect()
    transaction = connection.begin()
    factory = sessionmaker(
        bind=connection,
        autoflush=False,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    session = factory()

    try:
        yield session
    finally:
        # Order matters: close the Session first, then roll back the outer
        # transaction that owns every write.
        session.close()
        if transaction.is_active:
            transaction.rollback()
        connection.close()
