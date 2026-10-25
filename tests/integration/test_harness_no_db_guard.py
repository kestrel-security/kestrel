# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`KESTREL_ASSERT_NO_DB=1` must fail a unit test that touches the database.

A guard that only warns is a guard that gets ignored, so this runs a real
pytest process with the real plugin (`kestrel.testing.no_db_guard`) and asserts
the inner test *failed*. Doing it in a subprocess is the only honest way: the
guard is armed per test by a hook, and a test cannot both be marked `unit` and
survive tripping it.
"""

from __future__ import annotations

import pytest

INNER_CONFTEST = """
pytest_plugins = ["kestrel.testing.no_db_guard"]
"""

INNER_TEST = """
import os
import pytest
from sqlalchemy import create_engine, text


@pytest.mark.unit
def test_unit_test_that_opens_a_database_connection():
    engine = create_engine(os.environ["KESTREL_TEST_TARGET_URL"])
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


@pytest.mark.integration
def test_integration_test_may_open_a_database_connection():
    engine = create_engine(os.environ["KESTREL_TEST_TARGET_URL"])
    with engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1


def test_unmarked_test_is_not_guarded():
    engine = create_engine(os.environ["KESTREL_TEST_TARGET_URL"])
    with engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1
"""


@pytest.fixture
def inner_suite(pytester: pytest.Pytester, test_database_url: str, monkeypatch: pytest.MonkeyPatch):
    pytester.makeconftest(INNER_CONFTEST)
    pytester.makepyfile(test_guarded=INNER_TEST)
    pytester.makeini("[pytest]\nmarkers =\n    unit: tier 1\n    integration: tier 2\n")
    # A reachable database, so a failure can only mean the guard fired -- not
    # that Postgres was unreachable.
    monkeypatch.setenv("KESTREL_TEST_TARGET_URL", test_database_url)
    return pytester


def test_guard_fails_a_unit_test_that_opens_a_connection(inner_suite, monkeypatch):
    monkeypatch.setenv("KESTREL_ASSERT_NO_DB", "1")

    result = inner_suite.runpytest_subprocess("-p", "no:randomly", "-p", "no:cacheprovider")

    result.assert_outcomes(failed=1, passed=2)
    result.stdout.fnmatch_lines(["*UnitTestDatabaseAccess*"])
    result.stdout.fnmatch_lines(["*is marked 'unit' but opened a database connection*"])


def test_guard_is_inert_when_the_variable_is_unset(inner_suite, monkeypatch):
    monkeypatch.delenv("KESTREL_ASSERT_NO_DB", raising=False)

    result = inner_suite.runpytest_subprocess("-p", "no:randomly", "-p", "no:cacheprovider")

    result.assert_outcomes(passed=3)
