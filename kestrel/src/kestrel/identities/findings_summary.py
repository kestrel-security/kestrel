# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identity findings posture rollup for Identity Explorer.

Groups findings on an identity by status, severity, and policy — labeled
counts for investigation, not a composite risk score.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.identity import Identity
from kestrel.db.models.policy import Policy, PolicyVersion

FINDINGS_SUMMARY_ITEM_LIMIT = 50
FINDINGS_SUMMARY_POLICY_LIMIT = 12


def identity_findings_summary(
    db: Session,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
) -> dict[str, Any] | None:
    """Rollup + capped item list for findings where subject is this identity."""
    identity = db.get(Identity, identity_id)
    if identity is None or identity.org_id != org_id:
        return None

    findings = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.subject_id == identity_id,
            )
            .order_by(
                case((Finding.status == FindingStatus.OPEN, 0), else_=1),
                Finding.last_seen_at.desc(),
                Finding.id.desc(),
            )
        ).all()
    )

    version_ids = {f.policy_version_id for f in findings}
    versions = (
        {v.id: v for v in db.scalars(select(PolicyVersion).where(PolicyVersion.id.in_(version_ids))).all()}
        if version_ids
        else {}
    )
    policy_ids = {v.policy_id for v in versions.values()}
    policies = {p.id: p for p in db.scalars(select(Policy).where(Policy.id.in_(policy_ids))).all()} if policy_ids else {}

    by_status: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_policy: dict[str, dict[str, Any]] = {}

    items: list[dict[str, Any]] = []
    for finding in findings:
        by_status[finding.status.value] += 1
        by_severity[finding.severity.value] += 1
        version = versions.get(finding.policy_version_id)
        policy = policies.get(version.policy_id) if version is not None else None
        slug = policy.slug if policy is not None else None
        title = policy.title if policy is not None else None
        if slug:
            bucket = by_policy.setdefault(
                slug,
                {
                    "policy_slug": slug,
                    "policy_title": title,
                    "open_count": 0,
                    "total_count": 0,
                    "list_path": f"/findings?subject_id={identity_id}&policy_slug={slug}",
                },
            )
            bucket["total_count"] += 1
            if finding.status == FindingStatus.OPEN:
                bucket["open_count"] += 1

        if len(items) < FINDINGS_SUMMARY_ITEM_LIMIT:
            items.append(
                {
                    "id": str(finding.id),
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "policy_slug": slug,
                    "policy_title": title,
                    "first_seen_at": finding.first_seen_at.isoformat(),
                    "last_seen_at": finding.last_seen_at.isoformat(),
                    "detail_path": f"/findings/{finding.id}",
                }
            )

    policy_rows = sorted(
        by_policy.values(),
        key=lambda r: (-int(r["open_count"]), -int(r["total_count"]), r["policy_slug"]),
    )[:FINDINGS_SUMMARY_POLICY_LIMIT]

    open_count = by_status.get(FindingStatus.OPEN.value, 0)
    return {
        "kind": "kestrel.identity.findings_summary",
        "as_of": datetime.now(UTC).isoformat(),
        "identity_id": str(identity_id),
        "total_count": len(findings),
        "open_count": open_count,
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_policy": policy_rows,
        "items": items,
        "items_truncated": len(findings) > len(items),
        "list_path": f"/findings?subject_id={identity_id}",
        "open_list_path": f"/findings?status=open&subject_id={identity_id}",
        "notes": ("Findings where this identity is the subject. Counts are labeled rollups — not an opaque risk score."),
    }
