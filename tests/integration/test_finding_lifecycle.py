# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- finding lifecycle across evaluations.

A finding is keyed by ``(policy, subject)``. Triage (mute, suppress,
exception) must survive re-evaluation, expiries must reopen, policy-scoped
exceptions must be honoured, and a new policy version must not orphan or
duplicate what the old one found. See ``kestrel.findings.lifecycle``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.db.models.finding import Exception_, Finding, FindingStatus
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.webhook import FINDING_OPENED
from kestrel.findings.investigation.status import apply_status_transition, create_finding_exception
from kestrel.findings.lifecycle import reopen_expired_deferrals
from kestrel.findings.mute import mute_finding_for_days
from kestrel.policies.authoring import publish_new_version, set_current_version_enabled
from kestrel.policies.packs import disable_pack
from kestrel.testing import make_operator
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.integration.finding_world import ALWAYS_MATCH, FindingWorld


def _triage(session: Session, finding: Finding, status: FindingStatus, operator_id: uuid.UUID) -> None:
    if status == FindingStatus.MUTED:
        mute_finding_for_days(finding, days=7)
    elif status == FindingStatus.EXCEPTION:
        create_finding_exception(session, finding=finding, reason="accepted", created_by_operator_id=operator_id)
    else:
        apply_status_transition(finding, status)
    session.flush()


# --- #4: triage survives re-evaluation --------------------------------------


@pytest.mark.parametrize("status", [FindingStatus.MUTED, FindingStatus.SUPPRESSED, FindingStatus.EXCEPTION])
def test_a_triaged_finding_keeps_its_status_and_is_not_duplicated(db_session: Session, status: FindingStatus):
    world = FindingWorld(db_session)
    world.identity()
    operator = make_operator(db_session, world.org)
    policy = world.policy()
    world.evaluate()
    [finding] = world.findings(policy)
    first_seen = finding.last_seen_at
    _triage(db_session, finding, status, operator.id)
    opened_before = world.deliveries(FINDING_OPENED)

    world.evaluate()

    findings = world.findings(policy)
    assert [f.id for f in findings] == [finding.id], "re-evaluation opened a duplicate"
    assert findings[0].status == status
    assert findings[0].last_seen_at >= first_seen
    assert world.deliveries(FINDING_OPENED) == opened_before


def test_a_triaged_finding_whose_subject_stops_matching_is_left_alone(db_session: Session):
    world = FindingWorld(db_session)
    identity = world.identity()
    policy = world.policy()
    world.evaluate()
    [finding] = world.findings(policy)
    mute_finding_for_days(finding, days=7)
    identity.deleted_at = datetime.now(UTC)
    db_session.flush()

    world.evaluate()

    assert db_session.get(Finding, finding.id).status == FindingStatus.MUTED


def test_older_duplicates_are_merged_into_the_latest_finding(db_session: Session):
    """Rows left by the old per-version reconciliation converge on one
    finding that carries the notes, watchers, assignee and triage."""
    world = FindingWorld(db_session)
    identity = world.identity()
    operator = make_operator(db_session, world.org)
    policy = world.policy()
    world.evaluate()
    [latest] = world.findings(policy)

    earlier = datetime.now(UTC) - timedelta(days=3)
    older = Finding(
        id=uuid.uuid4(),
        org_id=world.org.id,
        policy_version_id=latest.policy_version_id,
        policy_evaluation_id=latest.policy_evaluation_id,
        title=latest.title,
        severity=latest.severity,
        status=FindingStatus.MUTED,
        muted_until=datetime.now(UTC) + timedelta(days=5),
        first_seen_at=earlier,
        last_seen_at=earlier,
        subject_type=latest.subject_type,
        subject_id=identity.id,
        assigned_to_operator_id=operator.id,
        created_at=earlier,
    )
    db_session.add(older)
    db_session.flush()
    db_session.add(
        FindingNote(id=uuid.uuid4(), org_id=world.org.id, finding_id=older.id, author_operator_id=operator.id, body="n")
    )
    db_session.add(FindingWatcher(id=uuid.uuid4(), org_id=world.org.id, finding_id=older.id, operator_id=operator.id))
    db_session.flush()

    world.evaluate()

    [survivor] = world.findings(policy)
    assert survivor.id == latest.id
    assert survivor.status == FindingStatus.MUTED
    assert survivor.assigned_to_operator_id == operator.id
    db_session.expire_all()
    assert db_session.scalars(select(FindingNote.finding_id)).all() == [survivor.id]
    assert db_session.scalars(select(FindingWatcher.finding_id).where(FindingWatcher.org_id == world.org.id)).all() == [
        survivor.id
    ]
    assert db_session.get(Finding, older.id).status == FindingStatus.RESOLVED


# --- #4: expiries reopen ---------------------------------------------------


def test_an_expired_mute_reopens_and_announces_it(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy()
    world.evaluate()
    expired, live = world.findings(policy)
    mute_finding_for_days(expired, days=1)
    mute_finding_for_days(live, days=1)
    expired.muted_until = datetime.now(UTC) - timedelta(minutes=1)
    db_session.flush()
    opened_before = world.deliveries(FINDING_OPENED)

    result = reopen_expired_deferrals(db_session, world.org.id)

    assert result.mutes_reopened == [expired.id]
    assert expired.status == FindingStatus.OPEN
    assert expired.muted_until is None
    assert live.status == FindingStatus.MUTED
    assert world.deliveries(FINDING_OPENED) == opened_before + 1
    [row] = world.audit(expired, "finding.auto_reopened")
    assert row.context["reason"] == "mute_expired"


def test_an_expired_finding_exception_reopens_but_a_live_or_undated_one_does_not(db_session: Session):
    world = FindingWorld(db_session)
    for _ in range(3):
        world.identity()
    operator = make_operator(db_session, world.org)
    policy = world.policy()
    world.evaluate()
    expired, live, plain = world.findings(policy)
    past = datetime.now(UTC) - timedelta(hours=1)
    create_finding_exception(db_session, finding=expired, reason="r", created_by_operator_id=operator.id, expires_at=past)
    create_finding_exception(
        db_session, finding=live, reason="r", created_by_operator_id=operator.id, expires_at=past + timedelta(days=2)
    )
    apply_status_transition(plain, FindingStatus.EXCEPTION)  # no exception row: nothing to expire
    db_session.flush()

    result = reopen_expired_deferrals(db_session, world.org.id)

    assert result.exceptions_reopened == [expired.id]
    assert (expired.status, live.status, plain.status) == (
        FindingStatus.OPEN,
        FindingStatus.EXCEPTION,
        FindingStatus.EXCEPTION,
    )


# --- #4: policy-scoped (GitOps) exceptions ----------------------------------


def test_a_live_policy_exception_records_matches_as_exceptions_until_it_expires(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    policy = world.policy()
    policy_exception = Exception_(
        id=uuid.uuid4(),
        org_id=world.org.id,
        finding_id=None,
        policy_id=policy.id,
        reason="accepted in gitops",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(policy_exception)
    db_session.flush()

    world.evaluate()

    [finding] = world.findings(policy)
    assert finding.status == FindingStatus.EXCEPTION
    assert world.deliveries(FINDING_OPENED) == 0

    policy_exception.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.flush()
    reopen_expired_deferrals(db_session, world.org.id)
    assert finding.status == FindingStatus.OPEN
    assert world.deliveries(FINDING_OPENED) == 1


# --- #6: policy versions ---------------------------------------------------


def test_publishing_a_new_version_keeps_the_same_findings(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    world.identity()
    policy = world.policy(description="v1")
    world.evaluate()
    before = {f.id for f in world.findings(policy)}
    opened_before = world.deliveries(FINDING_OPENED)

    slug = policy.slug
    publish_new_version(db_session, policy=policy, source_text=ALWAYS_MATCH.format(slug=slug, description="typo fixed"))
    db_session.flush()
    assert {f.policy_version_id for f in world.findings(policy)} == {policy.current_version_id}

    world.evaluate()

    after = world.findings(policy)
    assert {f.id for f in after} == before
    assert all(f.status == FindingStatus.OPEN for f in after)
    assert world.deliveries(FINDING_OPENED) == opened_before


def test_disabling_a_policy_resolves_its_findings_with_a_reason(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    policy = world.policy()
    world.evaluate()
    [finding] = world.findings(policy)
    delivery_ids: list = []

    set_current_version_enabled(db_session, policy=policy, is_enabled=False, webhook_delivery_ids=delivery_ids)

    assert world.findings(policy) == []
    assert finding.status == FindingStatus.RESOLVED
    [row] = world.audit(finding, "finding.auto_resolved")
    assert row.context["reason"] == "policy_disabled"
    assert len(delivery_ids) == 1


def test_disabling_a_pack_resolves_its_policies_findings(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    policy = world.policy()
    policy.pack_name = "lifecycle-pack"
    world.evaluate()
    assert len(world.findings(policy)) == 1

    disable_pack(db_session, world.org.id, "lifecycle-pack")

    assert world.findings(policy) == []
