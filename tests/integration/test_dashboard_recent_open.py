# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The dashboard's "Recent open findings" widget shows distinct policies.

Every finding from one policy evaluation shares a `last_seen_at`, so ordering
by time alone lets a single policy fill the whole widget. A demo estate showed
four copies of one title in the four rows the widget has -- which says strictly
less than four different titles in the same space, on the page a reader sees
first.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from kestrel.dashboard.overview import RECENT_OPEN_LIMIT, posture_overview
from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.testing import make_organization
from sqlalchemy.orm import Session


def _policy_with_findings(session: Session, org, *, slug: str, count: int, newest: datetime) -> None:
    """One policy whose `count` findings all share the same `last_seen_at`."""
    policy = Policy(id=uuid.uuid4(), org_id=org.id, slug=slug, title=slug, source=PolicySource.CUSTOM)
    session.add(policy)
    session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=1,
        source_text="",
        severity=Severity.HIGH,
        compliance_mappings={},
    )
    session.add(version)
    session.flush()
    policy.current_version_id = version.id
    evaluation = PolicyEvaluation(
        id=uuid.uuid4(),
        org_id=org.id,
        policy_version_id=version.id,
        started_at=newest,
        status=PolicyEvaluationStatus.SUCCESS,
    )
    session.add(evaluation)
    session.flush()
    for _ in range(count):
        session.add(
            Finding(
                id=uuid.uuid4(),
                org_id=org.id,
                policy_version_id=version.id,
                policy_evaluation_id=evaluation.id,
                title=f"Finding from {slug}",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                first_seen_at=newest,
                last_seen_at=newest,
                subject_type=FindingSubjectType.IDENTITY,
                subject_id=uuid.uuid4(),
            )
        )
    session.flush()


def test_one_noisy_policy_does_not_fill_the_recent_widget(db_session: Session):
    org = make_organization(db_session)
    now = datetime.now(UTC)

    # The noisy one is also the most recent, so a plain `last_seen_at DESC`
    # returns nothing but its findings.
    _policy_with_findings(db_session, org, slug="noisy", count=RECENT_OPEN_LIMIT + 4, newest=now)
    for index in range(3):
        _policy_with_findings(
            db_session,
            org,
            slug=f"quiet-{index}",
            count=1,
            newest=now - timedelta(minutes=index + 1),
        )

    recent = posture_overview(db_session, org.id)["findings"]["recent_open"]

    titles = [item["title"] for item in recent]
    assert titles[0] == "Finding from noisy", "the newest policy should still lead"
    assert len(set(titles)) == len(titles), f"the widget repeated a policy: {titles}"
    assert set(titles) == {
        "Finding from noisy",
        "Finding from quiet-0",
        "Finding from quiet-1",
        "Finding from quiet-2",
    }


def test_the_widget_still_fills_up_when_there_are_enough_policies(db_session: Session):
    """De-duplicating must not shrink the widget below what it can show."""
    org = make_organization(db_session)
    now = datetime.now(UTC)
    for index in range(RECENT_OPEN_LIMIT + 2):
        _policy_with_findings(
            db_session,
            org,
            slug=f"policy-{index}",
            count=2,
            newest=now - timedelta(minutes=index),
        )

    recent = posture_overview(db_session, org.id)["findings"]["recent_open"]

    assert len(recent) == RECENT_OPEN_LIMIT
    assert len({item["title"] for item in recent}) == RECENT_OPEN_LIMIT
