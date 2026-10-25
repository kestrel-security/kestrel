# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Move a completed sync run (and everything it wrote) into the past.

Why post-hoc rather than a clock parameter on `run_sync`: threading a `now=`
through would look cleaner, but `detect_deletions` compares `last_seen_at <
run_started_at`, and `last_seen_at` is set independently inside
`upsert_provenance_objects`. Backdating only the run timestamp would silently
disable deletion detection for every seeded step, so keeping them coherent means
threading a clock through `UpsertContext` as well -- a real change to the sync
engine for a demo-only benefit.

Rewriting the timestamps *after* the run has committed its diff cannot
desynchronize the two, because the diff has already been computed against real
wall-clock values. Nothing in production reads these rows expecting them to
agree with the row's `created_at`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorRun
from kestrel.db.models.event import Event
from kestrel.db.models.finding import Finding
from kestrel.db.models.policy import PolicyEvaluation

# Days between timeline steps.
STEP_SPACING_DAYS = 12

# How recent the newest step is. The last step has to land inside the default
# 7-day Changes window and the 0-7 day finding-age bucket, or the two views an
# operator opens first are both empty on a freshly seeded demo.
NEWEST_STEP_AGE_DAYS = 2

# How far back the baseline sync is dated. Sits one full step before the oldest
# timeline entry, so findings that have existed since the tenant was connected
# land in the dashboard's 90-day-plus bucket while drift findings fill the
# newer ones.
BASELINE_AGE_DAYS = 96


def step_age_days(index: int, total: int) -> int:
    """Age in days of timeline step `index`, oldest first.

    The newest step is `NEWEST_STEP_AGE_DAYS` old rather than exactly today, so
    the demo does not look like everything happened during the walkthrough.
    """
    return STEP_SPACING_DAYS * (total - 1 - index) + NEWEST_STEP_AGE_DAYS


def backdate_run(
    session: Session,
    *,
    run_id: uuid.UUID,
    occurred_at: datetime,
) -> None:
    """Move one run, its change events, and its evaluations to `occurred_at`."""
    session.execute(
        update(ConnectorRun)
        .where(ConnectorRun.id == run_id)
        .values(
            started_at=occurred_at,
            finished_at=occurred_at + timedelta(seconds=42),
        )
    )
    session.execute(update(Event).where(Event.connector_run_id == run_id).values(detected_at=occurred_at))
    session.execute(
        update(PolicyEvaluation)
        .where(PolicyEvaluation.connector_run_id == run_id)
        .values(started_at=occurred_at, finished_at=occurred_at + timedelta(seconds=3))
    )

    # Finding ages drive the dashboard's aging buckets and the
    # `open_older_than_days` filter, both of which are useless when every
    # finding is minutes old. `first_seen_at` only moves backwards -- a finding
    # carried forward from an earlier step keeps the date it actually appeared.
    evaluation_ids = select(PolicyEvaluation.id).where(PolicyEvaluation.connector_run_id == run_id)
    session.execute(
        update(Finding)
        .where(
            Finding.policy_evaluation_id.in_(evaluation_ids),
            Finding.first_seen_at > occurred_at,
        )
        .values(first_seen_at=occurred_at)
    )
    session.execute(update(Finding).where(Finding.policy_evaluation_id.in_(evaluation_ids)).values(last_seen_at=occurred_at))
    session.flush()
