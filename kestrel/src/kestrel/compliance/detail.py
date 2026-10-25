# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Compliance control detail: mapped policies + finding-backed evidence.

Shared by the API so the router does not re-implement policy lookup or
open/total finding counts used by the GRC control drill-down UI.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from kestrel.db.models.compliance import ComplianceControl, PolicyControlMapping
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Policy, PolicyVersion

# Detail responses are not paginated; cap open findings so a noisy control
# cannot blow up the payload. UI can deep-link to /findings for the rest.
OPEN_FINDINGS_LIMIT = 50


def get_control_for_org(db: Session, control_id: uuid.UUID, org_id: uuid.UUID) -> ComplianceControl | None:
    """Built-in controls (`org_id` null) are visible to every org; custom
    controls are org-scoped."""
    control = db.get(ComplianceControl, control_id)
    if control is None:
        return None
    if control.org_id is not None and control.org_id != org_id:
        return None
    return control


def _policy_ids_for_control(db: Session, control_id: uuid.UUID, org_id: uuid.UUID) -> list[uuid.UUID]:
    mappings = db.scalars(select(PolicyControlMapping).where(PolicyControlMapping.compliance_control_id == control_id)).all()
    mapped_ids = [m.policy_id for m in mappings]
    if not mapped_ids:
        return []
    return list(db.scalars(select(Policy.id).where(Policy.org_id == org_id, Policy.id.in_(mapped_ids))).all())


def _policy_version_ids(db: Session, policy_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    if not policy_ids:
        return []
    return list(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id.in_(policy_ids))).all())


def _count_findings(
    db: Session,
    *,
    org_id: uuid.UUID,
    version_ids: list[uuid.UUID],
    status: FindingStatus | None = None,
) -> int:
    if not version_ids:
        return 0
    stmt = (
        select(func.count()).select_from(Finding).where(Finding.policy_version_id.in_(version_ids), Finding.org_id == org_id)
    )
    if status is not None:
        stmt = stmt.where(Finding.status == status)
    return db.scalar(stmt) or 0


def control_list_summary(db: Session, control: ComplianceControl, org_id: uuid.UUID) -> dict:
    """List-row enrichment: mapped policy count + open findings for this org."""
    org_policy_ids = _policy_ids_for_control(db, control.id, org_id)
    version_ids = _policy_version_ids(db, org_policy_ids)
    return {
        "id": control.id,
        "framework": control.framework.value,
        "control_id": control.control_id,
        "title": control.title,
        "description": control.description,
        "mapped_policy_count": len(org_policy_ids),
        "open_finding_count": _count_findings(db, org_id=org_id, version_ids=version_ids, status=FindingStatus.OPEN),
    }


def _serialize_control_findings(
    db: Session,
    *,
    org_id: uuid.UUID,
    findings: list[Finding],
) -> list[dict]:
    if not findings:
        return []

    used_version_ids = {f.policy_version_id for f in findings}
    versions = {v.id: v for v in db.scalars(select(PolicyVersion).where(PolicyVersion.id.in_(used_version_ids))).all()}
    policy_ids = {v.policy_id for v in versions.values()}
    policies = {p.id: p for p in db.scalars(select(Policy).where(Policy.id.in_(policy_ids), Policy.org_id == org_id)).all()}

    out: list[dict] = []
    for finding in findings:
        version = versions.get(finding.policy_version_id)
        policy = policies.get(version.policy_id) if version else None
        row = {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "subject_type": finding.subject_type.value,
            "subject_id": finding.subject_id,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
            "policy_version_id": finding.policy_version_id,
            "policy_id": policy.id if policy else None,
            "policy_slug": policy.slug if policy else None,
            "detail_path": f"/findings/{finding.id}",
        }
        if finding.muted_until is not None:
            row["muted_until"] = finding.muted_until.isoformat()
        out.append(row)
    return out


def _open_findings(
    db: Session,
    *,
    org_id: uuid.UUID,
    version_ids: list[uuid.UUID],
    limit: int = OPEN_FINDINGS_LIMIT,
) -> list[dict]:
    if not version_ids:
        return []

    findings = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.policy_version_id.in_(version_ids),
                Finding.status == FindingStatus.OPEN,
            )
            .order_by(Finding.last_seen_at.desc(), Finding.id.desc())
            .limit(limit)
        ).all()
    )
    return _serialize_control_findings(db, org_id=org_id, findings=findings)


def _findings_with_active_exceptions(
    db: Session,
    *,
    org_id: uuid.UUID,
    version_ids: list[uuid.UUID],
    limit: int = OPEN_FINDINGS_LIMIT,
) -> list[dict]:
    """Findings for mapped policies that have a non-expired exception."""
    from datetime import UTC, datetime

    from kestrel.db.models.finding import Exception_

    if not version_ids:
        return []

    now = datetime.now(UTC)
    # Distinct findings that still have an active exception row.
    finding_ids = list(
        db.scalars(
            select(Exception_.finding_id)
            .where(
                Exception_.org_id == org_id,
                Exception_.finding_id.is_not(None),
                or_(Exception_.expires_at.is_(None), Exception_.expires_at > now),
            )
            .distinct()
        ).all()
    )
    if not finding_ids:
        return []

    findings = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.policy_version_id.in_(version_ids),
                Finding.id.in_(finding_ids),
            )
            .order_by(Finding.last_seen_at.desc(), Finding.id.desc())
            .limit(limit)
        ).all()
    )
    return _serialize_control_findings(db, org_id=org_id, findings=findings)


def _muted_findings(
    db: Session,
    *,
    org_id: uuid.UUID,
    version_ids: list[uuid.UUID],
    limit: int = OPEN_FINDINGS_LIMIT,
) -> list[dict]:
    """Muted findings for mapped policies — temporary snoozes vs exceptions."""
    if not version_ids:
        return []

    findings = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.policy_version_id.in_(version_ids),
                Finding.status == FindingStatus.MUTED,
            )
            .order_by(Finding.muted_until.asc().nulls_last(), Finding.last_seen_at.desc(), Finding.id.desc())
            .limit(limit)
        ).all()
    )
    return _serialize_control_findings(db, org_id=org_id, findings=findings)
