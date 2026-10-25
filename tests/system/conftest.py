# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 -- system. CLI end-to-end, migration replay, compose smoke.

Slower than the PR gate tolerates; runs post-merge and nightly. The reason
destructive setup is allowed here at all is the per-worker database: a system
test that drops and rebuilds a schema affects only the worker that ran it,
which is precisely what the old suite got wrong when `tests/e2e` ran
`DROP SCHEMA public CASCADE` against the shared development database.

Still bound by rule 5: writes go to `tmp_path`, never into the repository, and
nothing here opens `REPO_ROOT/.env`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_TIER_DIR = Path(__file__).parent


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        path = getattr(item, "path", None)
        if path is not None and _TIER_DIR in path.parents:
            item.add_marker("system")


@pytest.fixture(scope="session", autouse=True)
def _worker_database(test_database_url: str) -> str:
    """Point this worker's process at its own database for the whole session."""
    return test_database_url
