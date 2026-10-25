# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- how much a finished sync re-evaluates, and evaluation retention.

The audit-log poll runs every few minutes; re-evaluating the whole org
after each one wrote ~100 `policy_evaluations` rows per poll, and nothing
pruned them.
"""

from __future__ import annotations

import uuid

from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.policy import PolicyEvaluation, PolicyVersion
from kestrel.findings.pipeline import evaluate_all_enabled_policies, evaluation_plan_for_run
from kestrel.retention.policy_evaluations import prune_policy_evaluations
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.integration.finding_world import EVENT_POLICY, FindingWorld

# --- #16: evaluation after an audit-log poll, and evaluation retention ------


def test_an_incremental_run_with_nothing_new_evaluates_nothing(db_session: Session):
    world = FindingWorld(db_session)
    run = world.new_run(incremental=True)

    plan = evaluation_plan_for_run(db_session, run)

    assert plan.evaluate is False


def test_an_incremental_run_evaluates_everything_while_an_earlier_evaluation_is_owed(db_session: Session):
    # A sync commits before it evaluates. If that evaluation failed, the next
    # quiet poll must not conclude there is nothing to evaluate.
    world = FindingWorld(db_session)
    earlier = world.new_run(incremental=True)
    earlier.evaluation_pending = True
    db_session.flush()
    run = world.new_run(incremental=True)

    plan = evaluation_plan_for_run(db_session, run)

    assert plan.evaluate is True
    assert plan.resource_types is None
    assert plan.reason == "earlier_evaluation_owed"


def test_an_incremental_run_with_new_activity_evaluates_only_activity_policies(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    identity_policy = world.policy()
    event_policy = world.policy(source=EVENT_POLICY)
    run = world.new_run(incremental=True)
    world.activity_event(run)

    plan = evaluation_plan_for_run(db_session, run)
    assert plan.evaluate is True
    assert plan.resource_types == frozenset({"event"})

    evaluations = evaluate_all_enabled_policies(db_session, world.org.id, resource_types=plan.resource_types)

    evaluated = {db_session.get(PolicyVersion, e.policy_version_id).policy_id for e in evaluations}
    assert event_policy.id in evaluated
    assert identity_policy.id not in evaluated


def test_an_incremental_run_that_changed_inventory_evaluates_everything(db_session: Session):
    world = FindingWorld(db_session)
    identity = world.identity()
    run = world.new_run(incremental=True)
    db_session.add(
        Event(
            id=uuid.uuid4(),
            org_id=world.org.id,
            connector_run_id=run.id,
            entity_type="identity",
            entity_id=identity.id,
            change_type=ChangeType.UPDATED,
            field_changes=[],
        )
    )

    plan = evaluation_plan_for_run(db_session, run)

    assert plan.evaluate is True
    assert plan.resource_types is None


def test_a_full_run_evaluates_everything(db_session: Session):
    world = FindingWorld(db_session)
    plan = evaluation_plan_for_run(db_session, world.run)
    assert plan.evaluate is True
    assert plan.resource_types is None


def test_pruning_keeps_the_newest_evaluations_and_any_a_finding_references(db_session: Session):
    world = FindingWorld(db_session)
    world.identity()
    policy = world.policy()
    for _ in range(5):
        world.evaluate()
    [finding] = world.findings(policy)
    opener = finding.policy_evaluation_id

    def evaluation_ids() -> set[uuid.UUID]:
        db_session.flush()
        return set(
            db_session.scalars(
                select(PolicyEvaluation.id)
                .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
                .where(PolicyVersion.policy_id == policy.id)
            ).all()
        )

    assert len(evaluation_ids()) == 5
    newest = db_session.scalars(
        select(PolicyEvaluation.id)
        .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyEvaluation.started_at.desc(), PolicyEvaluation.id.desc())
        .limit(2)
    ).all()

    preview = prune_policy_evaluations(db_session, org_id=world.org.id, keep_per_policy=2, dry_run=True)
    assert len(evaluation_ids()) == 5

    result = prune_policy_evaluations(db_session, org_id=world.org.id, keep_per_policy=2)

    assert evaluation_ids() == {*newest, opener}
    assert preview.pruned == result.pruned >= 2
