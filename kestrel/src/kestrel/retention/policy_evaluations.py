# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Retention for `policy_evaluations` run history.

Every evaluation pass writes one `PolicyEvaluation` row per enabled policy, so
the table grows with sync frequency times policy count and nothing else ever
removes a row. The history is useful (the policy page lists recent runs, a
connector run's detail page lists the evaluations it triggered), but only the
recent end of it.

`prune_policy_evaluations` keeps the newest `keep_per_policy` rows per policy,
across all of its versions, and never deletes a row a finding still points at
(`findings.policy_evaluation_id` records the evaluation that first opened it).
Like the rest of this package it is an explicit operator action
(`kestrel retention prune-policy-evaluations`), not a scheduled one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, exists, func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.policy import PolicyEvaluation, PolicyVersion

#: Matches the largest page `GET /policies/{id}/evaluations` will serve.
DEFAULT_KEEP_PER_POLICY = 100


@dataclass
class PruneResult:
    keep_per_policy: int
    dry_run: bool
    pruned: int


def prune_policy_evaluations(
    session: Session,
    *,
    org_id: uuid.UUID,
    keep_per_policy: int = DEFAULT_KEEP_PER_POLICY,
    dry_run: bool = False,
) -> PruneResult:
    """Deletes all but the newest ``keep_per_policy`` evaluations of each
    policy in the org, sparing any evaluation a finding references.

    Does not commit -- the caller owns the transaction.
    """
    if keep_per_policy < 1:
        raise ValueError("keep_per_policy must be >= 1")

    ranked = (
        select(
            PolicyEvaluation.id.label("id"),
            func.row_number()
            .over(
                partition_by=PolicyVersion.policy_id,
                order_by=(PolicyEvaluation.started_at.desc(), PolicyEvaluation.id.desc()),
            )
            .label("rn"),
        )
        .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
        .where(PolicyEvaluation.org_id == org_id)
        .subquery()
    )
    referenced = exists().where(Finding.policy_evaluation_id == ranked.c.id)
    doomed = select(ranked.c.id).where(ranked.c.rn > keep_per_policy, ~referenced)

    if dry_run:
        count = session.scalar(select(func.count()).select_from(doomed.subquery())) or 0
        return PruneResult(keep_per_policy=keep_per_policy, dry_run=True, pruned=int(count))

    session.flush()
    deleted = session.execute(
        delete(PolicyEvaluation)
        .where(PolicyEvaluation.org_id == org_id, PolicyEvaluation.id.in_(doomed))
        .execution_options(synchronize_session=False)
    )
    return PruneResult(keep_per_policy=keep_per_policy, dry_run=False, pruned=int(getattr(deleted, "rowcount", 0) or 0))
