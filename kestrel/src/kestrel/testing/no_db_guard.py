# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""A pytest plugin that makes Tier 1 purity enforced rather than trusted.

Enable it by setting ``KESTREL_ASSERT_NO_DB=1``. Any test marked ``unit`` that
opens a database connection then fails loudly, instead of quietly turning a
"pure logic, no I/O" tier into one that needs Postgres running.

Registered from the repository's root ``conftest.py`` via ``pytest_plugins``.
It is importable as ``kestrel.testing.no_db_guard`` so a downstream connector
suite can enable the same rule with ``-p kestrel.testing.no_db_guard``.

Deliberately imports no ``pytest``: the hook functions below are found by name,
and ``item`` arrives as an argument. That keeps ``kestrel.testing`` free of a
test-framework import even in this, its most test-coupled module.
"""

from __future__ import annotations

import os
from typing import Any

ENV_VAR = "KESTREL_ASSERT_NO_DB"
UNIT_MARKER = "unit"

_TRUTHY = {"1", "true", "yes", "on"}

# Node id of the unit-marked test currently running, or None when the guard
# should stand down (no test running, or a test that is allowed a database).
_armed_for: str | None = None


class UnitTestDatabaseAccess(AssertionError):
    """A test marked ``unit`` tried to reach the database."""


def guard_enabled() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in _TRUTHY


def _refuse(what: str) -> None:
    raise UnitTestDatabaseAccess(
        f"{_armed_for} is marked '{UNIT_MARKER}' but opened a database connection ({what}). "
        f"Tier 1 tests must be pure: no DB, no network, no subprocess. Move it to "
        f"tests/integration/ and mark it 'integration', or drop the database dependency. "
        f"(This check is active because {ENV_VAR} is set.)"
    )


def _on_dbapi_connect(dbapi_connection: Any, connection_record: Any) -> None:
    """SQLAlchemy ``connect``: a brand-new DBAPI connection was established."""
    if _armed_for is not None:
        _refuse("new DBAPI connection")


def _on_engine_connect(connection: Any) -> None:
    """SQLAlchemy ``engine_connect``: ``Engine.connect()`` was called.

    Needed alongside ``connect`` because a pooled connection opened earlier in
    the worker process is reused without firing ``connect`` again -- and under
    ``-p randomly`` a unit test routinely runs after an integration test that
    already filled the pool.
    """
    if _armed_for is not None:
        _refuse("Engine.connect()")


def pytest_configure(config: Any) -> None:
    if not guard_enabled():
        return
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    event.listen(Engine, "connect", _on_dbapi_connect)
    event.listen(Engine, "engine_connect", _on_engine_connect)


def pytest_runtest_setup(item: Any) -> None:
    # Arms before fixture setup: this plugin is registered long after
    # _pytest.runner, and pytest calls hook implementations last-registered-
    # first, so this runs before the runner's own setup impl invokes fixtures.
    global _armed_for
    _armed_for = item.nodeid if item.get_closest_marker(UNIT_MARKER) else None


def pytest_runtest_teardown(item: Any) -> None:
    global _armed_for
    _armed_for = None
