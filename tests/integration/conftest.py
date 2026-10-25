# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- integration. Real Postgres, real session, fixture transports.

Everything here runs against this xdist worker's own database (see the root
`conftest.py`), inside a transaction that is rolled back. Tests ask for
`db_session`; the autouse fixture below covers the rest by pointing
`DATABASE_URL` and the memoized `kestrel.db.session` Engine at the worker
database for the whole session, so code that reaches `get_engine()` directly --
a Celery task run eagerly, a CLI helper -- cannot end up on the developer's
database.

No network. Live HTTP goes through `httpx.MockTransport` via the connector
SDK's `transport=` seam, or through `kestrel.testing.RecordingTransport`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_TIER_DIR = Path(__file__).parent


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        path = getattr(item, "path", None)
        if path is not None and _TIER_DIR in path.parents:
            item.add_marker("integration")


@pytest.fixture(scope="session", autouse=True)
def _worker_database(test_database_url: str) -> str:
    """Point this worker's process at its own database for the whole session."""
    return test_database_url
