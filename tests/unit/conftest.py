# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- unit. Pure logic: no database, no network, no subprocess.

Every test collected under this directory is marked `unit` automatically, so a
test file never has to remember. `KESTREL_ASSERT_NO_DB=1` turns the tier's
purity from a convention into a failure (see `kestrel.testing.no_db_guard`).

There is no autouse fixture here on purpose: a tier whose tests need setup to
be pure is not pure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_TIER_DIR = Path(__file__).parent


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    # Called with every collected item, not just this directory's, so the
    # subtree check is what keeps the marker scoped.
    for item in items:
        path = getattr(item, "path", None)
        if path is not None and _TIER_DIR in path.parents:
            item.add_marker("unit")
