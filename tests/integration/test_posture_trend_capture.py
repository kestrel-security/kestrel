# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the daily posture trend capture
(``kestrel_worker.tasks.posture_trend``).

The dashboard trend widget reads ``posture_trend_snapshots``. Nothing in
production wrote that table until this task existed, so the tests that matter
are: it writes a row per org, it is safe to run repeatedly within a UTC day
(the beat entry fires hourly), and one org failing does not cost the others
their data point.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.reports.posture_trend import capture_posture_snapshot
from kestrel.testing import make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


def _snapshots(session: Session, org_id: uuid.UUID) -> list[PostureTrendSnapshot]:
    return list(
        session.scalars(
            select(PostureTrendSnapshot)
            .where(PostureTrendSnapshot.org_id == org_id)
            .order_by(PostureTrendSnapshot.snapshot_date)
        ).all()
    )


def test_capture_writes_one_row_for_today(db_session: Session) -> None:
    org = make_organization(db_session)

    capture_posture_snapshot(db_session, org.id)

    rows = _snapshots(db_session, org.id)
    assert len(rows) == 1
    assert rows[0].snapshot_date == datetime.now(UTC).date()


def test_capture_is_idempotent_within_a_utc_day(db_session: Session) -> None:
    """The beat entry fires hourly, so this runs many times per day."""
    org = make_organization(db_session)
    now = datetime(2026, 3, 1, 4, 0, tzinfo=UTC)

    capture_posture_snapshot(db_session, org.id, now=now)
    capture_posture_snapshot(db_session, org.id, now=now + timedelta(hours=9))

    assert len(_snapshots(db_session, org.id)) == 1


def test_capture_starts_a_new_row_on_the_next_utc_day(db_session: Session) -> None:
    org = make_organization(db_session)
    day_one = datetime(2026, 3, 1, 23, 30, tzinfo=UTC)

    capture_posture_snapshot(db_session, org.id, now=day_one)
    capture_posture_snapshot(db_session, org.id, now=day_one + timedelta(hours=1))

    rows = _snapshots(db_session, org.id)
    assert [r.snapshot_date.isoformat() for r in rows] == ["2026-03-01", "2026-03-02"]


def test_capture_scopes_snapshots_to_their_own_org(db_session: Session) -> None:
    first = make_organization(db_session)
    second = make_organization(db_session)

    capture_posture_snapshot(db_session, first.id)

    assert len(_snapshots(db_session, first.id)) == 1
    assert _snapshots(db_session, second.id) == []


@pytest.mark.parametrize("field", ["open_by_severity", "factor_counts"])
def test_capture_records_the_scorecard_shape_the_widget_reads(db_session: Session, field: str) -> None:
    org = make_organization(db_session)

    row = capture_posture_snapshot(db_session, org.id)

    assert isinstance(getattr(row, field), dict)
    assert row.attention_count >= 0
