# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Root pytest configuration: environment, per-worker databases, transactions.

Read `docs/testing.md` first -- this file is that document's
implementation. Three things happen here and nowhere else:

1. **The test environment is fixed before anything imports `kestrel`.** The
   assignments below run at conftest import, which pytest performs before it
   imports a single test module, so `kestrel.auth.passwords` (Argon2 parameters
   read at import) and `kestrel_api.middleware.rate_limit` (settings read at
   import) see the test values rather than production defaults.

2. **Each xdist worker gets its own database**, cloned from a template that
   carries the migrations. A worker owns its database outright, so `-n auto` is
   safe and a system test that resets a schema harms nobody.

3. **Each test runs inside a transaction that is rolled back**, with
   application-level `commit()` neutralised down to a savepoint release.

Nothing here writes inside the repository.
"""

from __future__ import annotations

import os

# --------------------------------------------------------------------------
# Environment. Assigned at import time, before the first `kestrel` import.
# --------------------------------------------------------------------------

# Tracing installs a process-global OpenTelemetry provider and the worker binds
# a metrics port. Neither belongs in a test process, and the second makes two
# xdist workers fight over a TCP port.
os.environ["KESTREL_ENABLE_OBSERVABILITY"] = "0"

# The measured lever, from profiling the suite: the subprocess policy
# runtime forks an interpreter per evaluation batch and pays ~517ms of `kestrel`
# import cost each time -- 133.4s vs 25.5s on one test file. `setdefault`, not
# assignment, so `KESTREL_POLICY_RUNTIME=subprocess uv run pytest ...` still
# works for the small set of tests that cover the subprocess isolation contract.
os.environ.setdefault("KESTREL_POLICY_RUNTIME", "restricted")

# Argon2id at production cost is 35ms/hash. Measured across the old suite's 49
# hashing sites that was 1.71s of a 468s run -- free to fix, but not a lever.
os.environ.setdefault("KESTREL_ARGON2_TIME_COST", "1")
os.environ.setdefault("KESTREL_ARGON2_MEMORY_COST", "8")
os.environ.setdefault("KESTREL_ARGON2_PARALLELISM", "1")

# Rate limiting is a fixed window over a process- or Redis-global bucket, i.e.
# shared mutable state between otherwise unrelated tests (rule 4). Turned off
# through its supported configuration rather than by reconfiguring the runtime
# singleton from an autouse fixture, which is what the old suite did. A test
# that is *about* rate limiting sets these back for itself.
os.environ.setdefault("KESTREL_RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("KESTREL_RATE_LIMIT_BACKEND", "memory")

import re
import time
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from kestrel.db.session import get_database_url, reset_engine
from kestrel.testing import make_master_key, savepoint_session
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

# Connector secrets are envelope-encrypted and the key is read from the
# environment. Tests do not load the developer's `.env` (rule 5), so the harness
# mints a throwaway key per worker process.
os.environ.setdefault("KESTREL_MASTER_KEY", make_master_key())

# The no-DB guard is inert unless KESTREL_ASSERT_NO_DB is set; `pytester` backs
# the self-test that proves the guard actually fails a test.
pytest_plugins = ("kestrel.testing.no_db_guard", "pytester")

REPO_ROOT = Path(__file__).resolve().parent

#: Migrations are applied once into this database; every worker database is a
#: `CREATE DATABASE ... TEMPLATE` clone of it. Reused across runs when its
#: alembic_version already matches head, which is what keeps startup cheap.
TEMPLATE_DATABASE = os.environ.get("KESTREL_TEST_TEMPLATE_DB", "")

#: Any database the harness is willing to create or drop must start with this.
#: The development database is named `kestrel`, and this prefix is the reason a
#: bug here cannot reach it.
#:
#: `KESTREL_TEST_DB_SLOT` appends a suffix, so two pytest runs sharing one
#: Postgres (concurrent agents, or a local run alongside CI against the same
#: server) do not both claim `kestrel_test_gw0` and drop each other's database
#: mid-test. Unset means the plain prefix, which is what a single run wants.
_DB_SLOT = os.environ.get("KESTREL_TEST_DB_SLOT", "").strip().lower()
if _DB_SLOT and not re.fullmatch(r"[a-z0-9_]+", _DB_SLOT):
    raise RuntimeError(f"KESTREL_TEST_DB_SLOT={_DB_SLOT!r} must be lowercase alphanumeric/underscore")
TEST_DATABASE_PREFIX = f"kestrel_test_{_DB_SLOT}_" if _DB_SLOT else "kestrel_test_"

#: Serialises template construction across workers. Advisory locks are held on
#: the maintenance connection and released when it closes, so a crashed worker
#: cannot wedge the next run.
if not TEMPLATE_DATABASE:
    TEMPLATE_DATABASE = f"{TEST_DATABASE_PREFIX}template"

TEMPLATE_LOCK_KEY = 0x4B455354 ^ (zlib.crc32(TEMPLATE_DATABASE.encode()) & 0x7FFFFFF)

_SAFE_DATABASE_NAME = re.compile(r"^[a-z0-9_]+$")


# --------------------------------------------------------------------------
# Tier markers for the test packages that live next to the code they cover.
# `tests/{unit,integration,system}/conftest.py` mark their own subtrees.
# --------------------------------------------------------------------------

_UNIT_TEST_ROOTS = ("connectors", "examples")

#: Tier 4 needs real tenant credentials, so it is opt-in rather than something
#: `uv run pytest` stumbles into. This is the tier's design (manual dispatch),
#: not a skip added to make a run green.
LIVE_TESTS_ENV_VAR = "KESTREL_RUN_LIVE_TESTS"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark package-local test directories as Tier 1, and gate Tier 4.

    Connector unit tests live in `tests/unit/connectors/`. The only package-local
    tests today are `examples/*/tests/`, which sit beside the example they cover
    because the example is not a workspace member. Marking `examples/` (and
    `connectors/`, should a connector ever carry its own tests) here means
    `-m unit` selects the whole tier no matter where a test file sits.
    """
    run_live = os.environ.get(LIVE_TESTS_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}
    live_skip = pytest.mark.skip(reason=f"live-tenant test; set {LIVE_TESTS_ENV_VAR}=1 to run")

    for item in items:
        if not run_live and item.get_closest_marker("live") is not None:
            item.add_marker(live_skip)
        path = getattr(item, "path", None)
        if path is None:
            continue
        try:
            relative = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            continue
        if relative.startswith(_UNIT_TEST_ROOTS):
            item.add_marker("unit")


# --------------------------------------------------------------------------
# Per-worker database provisioning.
# --------------------------------------------------------------------------


def _worker_id() -> str:
    """`gw0`, `gw1`, ... under xdist; `main` for a serial (`-n0`) run."""
    return os.environ.get("PYTEST_XDIST_WORKER", "main")


def _assert_disposable(name: str) -> str:
    """Refuse to touch anything that is not one of our own test databases."""
    if not name.startswith(TEST_DATABASE_PREFIX) or not _SAFE_DATABASE_NAME.match(name):
        raise RuntimeError(
            f"refusing to create or drop database {name!r}: the harness only manages "
            f"lowercase names starting with {TEST_DATABASE_PREFIX!r}"
        )
    return name


def _base_url() -> URL:
    return make_url(get_database_url())


def _url_for(database: str) -> URL:
    return _base_url().set(database=database)


def _maintenance_engine() -> Engine:
    """AUTOCOMMIT connection to `postgres`: CREATE/DROP DATABASE cannot run
    inside a transaction block, and must not run from the database being
    dropped."""
    return create_engine(_url_for("postgres"), isolation_level="AUTOCOMMIT", poolclass=NullPool)


def _terminate_connections(connection: object, database: str) -> None:
    connection.execute(  # type: ignore[attr-defined]
        text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :name AND pid <> pg_backend_pid()"),
        {"name": database},
    )


def _drop_database(connection: object, database: str) -> None:
    _assert_disposable(database)
    _terminate_connections(connection, database)
    connection.execute(text(f'DROP DATABASE IF EXISTS "{database}"'))  # type: ignore[attr-defined]


def _alembic_config() -> object:
    from alembic.config import Config

    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    return config


def _alembic_head() -> str:
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    if head is None:
        raise RuntimeError("alembic reports no head revision; migrations/ looks empty")
    return head


def _template_matches_head(head: str) -> bool:
    """True when the template exists and already carries the current migrations.

    `migrations/env.py` reads DATABASE_URL from the environment, so a stale
    template would otherwise be reused silently after a migration lands. Uses
    NullPool and disposes immediately: Postgres refuses
    `CREATE DATABASE ... TEMPLATE` while anyone is connected to the template.
    """
    engine = create_engine(_url_for(TEMPLATE_DATABASE), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            versions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    except SQLAlchemyError:
        return False  # missing database, missing table: rebuild either way
    finally:
        engine.dispose()
    return list(versions) == [head]


def _apply_migrations(url: URL) -> None:
    from alembic import command

    # migrations/env.py takes its URL from DATABASE_URL, not from the Config
    # object, so this is the supported way to point it somewhere else.
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    try:
        command.upgrade(_alembic_config(), "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def _clone_template(connection: object, database: str) -> None:
    """`CREATE DATABASE database TEMPLATE ...`, retrying past stray sessions.

    Postgres rejects the clone with SQLSTATE 55006 while any session is
    connected to the template. We hold the advisory lock, so a competing worker
    is not mid-migration -- what remains is a connection that has not finished
    closing, or one left by a killed process. Terminate and retry.
    """
    last_error: Exception | None = None
    for _attempt in range(6):
        try:
            connection.execute(  # type: ignore[attr-defined]
                text(f'CREATE DATABASE "{database}" TEMPLATE "{TEMPLATE_DATABASE}"')
            )
            return
        except DBAPIError as exc:
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if sqlstate != "55006":
                raise
            last_error = exc
            _terminate_connections(connection, TEMPLATE_DATABASE)
            time.sleep(0.2)  # provisioning, not a test: let the backends exit
    raise RuntimeError(
        f"could not clone {TEMPLATE_DATABASE!r} into {database!r}: still in use after 6 attempts"
    ) from last_error


def _provision_worker_database() -> str:
    """Create this worker's database from an up-to-date template. Returns its URL."""
    database = _assert_disposable(f"{TEST_DATABASE_PREFIX}{_worker_id()}")
    _assert_disposable(TEMPLATE_DATABASE)
    head = _alembic_head()

    engine = _maintenance_engine()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": TEMPLATE_LOCK_KEY})
            try:
                if not _template_matches_head(head):
                    _drop_database(connection, TEMPLATE_DATABASE)
                    connection.execute(text(f'CREATE DATABASE "{TEMPLATE_DATABASE}"'))
                    _apply_migrations(_url_for(TEMPLATE_DATABASE))
                _drop_database(connection, database)
                _clone_template(connection, database)
            finally:
                connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": TEMPLATE_LOCK_KEY})
    finally:
        engine.dispose()
    return _url_for(database).render_as_string(hide_password=False)


def _drop_worker_database(database: str) -> None:
    engine = _maintenance_engine()
    try:
        with engine.connect() as connection:
            _drop_database(connection, database)
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# Fixtures.
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def worker_id() -> str:
    """`gw0`, `gw1`, ... under xdist; `main` for a serial run."""
    return _worker_id()


@pytest.fixture(scope="session")
def worker_database_name(worker_id: str) -> str:
    """This worker's database name, built the same way the harness builds it.

    A fixture rather than a literal in each test: the name depends on
    `KESTREL_TEST_DB_SLOT`, and a test that hardcodes `kestrel_test_<worker>`
    passes in the default slot and fails in every other one.
    """
    return f"{TEST_DATABASE_PREFIX}{worker_id}"


@pytest.fixture(scope="session")
def test_database_url(worker_id: str) -> Iterator[str]:
    """This worker's private database, with `DATABASE_URL` pointed at it.

    Session-scoped and lazy: a Tier 1 run never reaches this, so unit tests do
    not need Postgres. Integration and system tiers pull it in via an autouse
    fixture in their own conftest, so code that reaches `get_engine()` without
    asking for a session still lands on the worker's database.
    """
    url = _provision_worker_database()
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    reset_engine()
    try:
        yield url
    finally:
        reset_engine()
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        if os.environ.get("KESTREL_KEEP_TEST_DATABASES", "").strip().lower() not in {"1", "true", "yes", "on"}:
            _drop_worker_database(make_url(url).database or "")


@pytest.fixture(scope="session")
def db_engine(test_database_url: str) -> Iterator[Engine]:
    """One Engine per worker for the whole session.

    The old suite built an Engine per test. That is pure waste: connection pool
    setup and dialect reflection repeated hundreds of times for a database whose
    URL never changes within a worker.
    """
    engine = create_engine(test_database_url, pool_pre_ping=True)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A Session whose writes never survive the test.

    Application code calling `commit()` works and its writes are visible for the
    rest of the test; the outer transaction is still rolled back at teardown.
    See `kestrel.testing.savepoint_session`.
    """
    with savepoint_session(db_engine) as session:
        yield session
