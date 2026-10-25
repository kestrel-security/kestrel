# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task: capture the daily posture trend snapshot for every org.

The dashboard's trend widget reads `posture_trend_snapshots`, and until this
task existed nothing in production ever wrote that table -- only the demo seed
did. A real deployment therefore showed a permanently empty trend, which reads
as a broken widget rather than as "history starts when you install".

`capture_posture_snapshot` is idempotent per UTC day (it upserts on
`(org_id, snapshot_date)`), so running it more than once a day is harmless and
a missed run costs that day's point, not the series. There is deliberately no
backfill: a snapshot records what posture was on the day it ran, and
synthesizing earlier days from today's findings would invent history.
"""

from __future__ import annotations

import logging

from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.reports.posture_trend import capture_posture_snapshot
from sqlalchemy import select

from kestrel_worker.celery_app import app

logger = logging.getLogger(__name__)


@app.task(name="kestrel.posture.capture_daily_snapshot")
def capture_daily_posture_snapshots() -> int:
    """Snapshot today's posture for every org. Returns the number captured."""
    session = get_sessionmaker()()
    captured = 0
    try:
        for org_id in session.scalars(select(Organization.id)).all():
            try:
                capture_posture_snapshot(session, org_id)
                session.commit()
                captured += 1
            except Exception:
                # One org's scorecard failing must not cost every other org
                # its data point for the day.
                session.rollback()
                logger.exception("posture trend snapshot failed for org %s", org_id)
        return captured
    finally:
        session.close()
