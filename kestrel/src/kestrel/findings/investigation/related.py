# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Other findings worth seeing alongside one: same subject, and same policy."""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Policy, PolicyVersion

RELATED_FINDINGS_LIMIT = 12
SAME_POLICY_COHORT_LIMIT = 12


def related_findings(
    db: Session,
    finding: Finding,
    *,
    limit: int = RELATED_FINDINGS_LIMIT,
) -> list[dict]:
    """Other findings on the same subject — open first, then newest last_seen."""
    cap = max(0, min(limit, RELATED_FINDINGS_LIMIT))
    if cap == 0:
        return []
    rows = db.scalars(
        select(Finding)
        .where(
            Finding.org_id == finding.org_id,
            Finding.subject_type == finding.subject_type,
            Finding.subject_id == finding.subject_id,
            Finding.id != finding.id,
        )
        .order_by(
            case((Finding.status == FindingStatus.OPEN, 0), else_=1),
            Finding.last_seen_at.desc(),
            Finding.id.desc(),
        )
        .limit(cap)
    ).all()
    return [
        {
            "id": row.id,
            "title": row.title,
            "severity": row.severity.value,
            "status": row.status.value,
            "first_seen_at": row.first_seen_at.isoformat(),
            "last_seen_at": row.last_seen_at.isoformat(),
        }
        for row in rows
    ]


def same_policy_cohort(
    db: Session,
    finding: Finding,
    *,
    limit: int = SAME_POLICY_COHORT_LIMIT,
) -> dict[str, Any]:
    """Other findings for the same policy (any version) — investigation cohort.

    Distinct from ``related_findings`` (same subject). Helps operators see how
    widespread a policy's findings are across the org.
    """
    cap = max(0, min(limit, SAME_POLICY_COHORT_LIMIT))
    version = db.get(PolicyVersion, finding.policy_version_id)
    if version is None:
        return {
            "policy_id": None,
            "policy_slug": None,
            "policy_title": None,
            "open_other_count": 0,
            "total_other_count": 0,
            "items": [],
            "list_path": None,
        }

    policy = db.get(Policy, version.policy_id)
    version_ids = list(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == version.policy_id)).all())
    if not version_ids:
        version_ids = [finding.policy_version_id]

    base_where = (
        Finding.org_id == finding.org_id,
        Finding.policy_version_id.in_(version_ids),
        Finding.id != finding.id,
    )
    total_other = db.scalar(select(func.count()).select_from(Finding).where(*base_where)) or 0
    open_other = (
        db.scalar(select(func.count()).select_from(Finding).where(*base_where, Finding.status == FindingStatus.OPEN)) or 0
    )

    items: list[dict[str, Any]] = []
    if cap > 0:
        rows = db.scalars(
            select(Finding)
            .where(*base_where)
            .order_by(
                case((Finding.status == FindingStatus.OPEN, 0), else_=1),
                Finding.last_seen_at.desc(),
                Finding.id.desc(),
            )
            .limit(cap)
        ).all()
        items = [
            {
                "id": str(row.id),
                "title": row.title,
                "severity": row.severity.value,
                "status": row.status.value,
                "subject_type": row.subject_type.value,
                "subject_id": str(row.subject_id),
                "first_seen_at": row.first_seen_at.isoformat(),
                "last_seen_at": row.last_seen_at.isoformat(),
                "detail_path": f"/findings/{row.id}",
            }
            for row in rows
        ]

    slug = policy.slug if policy is not None else None
    return {
        "policy_id": str(version.policy_id),
        "policy_slug": slug,
        "policy_title": policy.title if policy is not None else None,
        "open_other_count": int(open_other),
        "total_other_count": int(total_other),
        "items": items,
        "list_path": f"/findings?status=open&policy_slug={slug}" if slug else "/findings?status=open",
    }
