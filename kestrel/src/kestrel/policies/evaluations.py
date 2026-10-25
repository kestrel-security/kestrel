# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Recent PolicyEvaluation history for a policy."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicyVersion

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def list_policy_evaluations(
    session: Session,
    *,
    org_id: uuid.UUID,
    policy_id: uuid.UUID,
    limit: int = DEFAULT_LIMIT,
) -> list[dict]:
    """Return recent evaluations for all versions of ``policy_id`` (newest first).

    Scoped by ``org_id`` via ``PolicyEvaluation.org_id`` and a join that
    ensures the version belongs to the requested policy.
    """
    capped = max(1, min(int(limit), MAX_LIMIT))
    rows = session.execute(
        select(PolicyEvaluation, PolicyVersion)
        .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
        .where(
            PolicyEvaluation.org_id == org_id,
            PolicyVersion.policy_id == policy_id,
        )
        .order_by(PolicyEvaluation.started_at.desc())
        .limit(capped)
    ).all()

    policy = session.get(Policy, policy_id)
    slug = policy.slug if policy is not None else None

    out: list[dict] = []
    for evaluation, version in rows:
        connector_run_path = (
            f"/connectors/runs/{evaluation.connector_run_id}" if evaluation.connector_run_id is not None else None
        )
        out.append(
            {
                "id": evaluation.id,
                "status": evaluation.status.value,
                "matched_object_count": evaluation.matched_object_count,
                "error_message": evaluation.error_message,
                "started_at": evaluation.started_at.isoformat() if evaluation.started_at else None,
                "finished_at": evaluation.finished_at.isoformat() if evaluation.finished_at else None,
                "policy_version_id": evaluation.policy_version_id,
                "policy_version": version.version,
                "connector_run_id": evaluation.connector_run_id,
                "connector_run_path": connector_run_path,
                "findings_list_path": f"/findings?policy_slug={slug}" if slug else None,
            }
        )
    return out
