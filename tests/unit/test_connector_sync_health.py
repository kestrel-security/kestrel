# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for sync-health classification.

`partial_failure` used to be dead: the enum value existed but nothing produced
it, and both classifiers folded it into "failed". Now that reduced-coverage runs
are real, a tenant that is *permanently* partial -- a GitHub Team plan has no
audit log API, so every run is -- must not sit permanently red, and must not be
reported as fully healthy either.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kestrel.connectors.health import HEALTH_STATUSES, classify_sync_health

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, "never"),
        ("pending", "running"),
        ("running", "running"),
        ("failed", "failed"),
        ("partial_failure", "degraded"),
        ("success", "healthy"),
    ],
)
def test_run_status_maps_to_a_health_state(status: str | None, expected: str) -> None:
    assert classify_sync_health(last_run_status=status, last_success_at=NOW - timedelta(minutes=5), now=NOW) == expected


def test_degraded_is_a_recognized_health_filter_value() -> None:
    assert "degraded" in HEALTH_STATUSES


def test_degraded_outranks_staleness_rather_than_stacking_with_it() -> None:
    # A partial run still refreshed the inventory. Reporting it as stale too
    # would show one problem as two.
    assert (
        classify_sync_health(
            last_run_status="partial_failure",
            last_success_at=NOW - timedelta(days=30),
            now=NOW,
        )
        == "degraded"
    )


def test_an_outright_failure_is_still_failed() -> None:
    assert classify_sync_health(last_run_status="failed", last_success_at=NOW, now=NOW) == "failed"
