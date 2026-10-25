# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared findings list filters, export rows, and open-aging rollups.

Used by the findings API (list + export) and dashboard posture overview so
filter semantics stay in one place.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.operator import Operator
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.findings.investigation.status import parse_finding_status

EXPORT_FINDINGS_MAX = 5000

# Exclusive open-age buckets for SLA-style posture (first_seen_at).
AGE_BUCKETS = (
    ("0_7", 0, 7),
    ("7_30", 7, 30),
    ("30_90", 30, 90),
    ("90_plus", 90, None),
)


class FindingListError(ValueError):
    """Invalid list/export filter combination."""


def _policy_slug(db: Session, policy_version_id: uuid.UUID) -> str | None:
    version = db.get(PolicyVersion, policy_version_id)
    if version is None:
        return None
    policy = db.get(Policy, version.policy_id)
    return policy.slug if policy is not None else None


def _assigned_to_out(db: Session, finding: Finding) -> dict | None:
    if finding.assigned_to_operator_id is None:
        return None
    operator = db.get(Operator, finding.assigned_to_operator_id)
    if operator is None:
        return None
    return {"id": operator.id, "email": operator.email, "display_name": operator.display_name}


def age_days_for(finding: Finding, *, now: datetime | None = None) -> int:
    """Whole days since first_seen_at (UTC)."""
    clock = now or datetime.now(UTC)
    first = finding.first_seen_at
    if first.tzinfo is None:
        first = first.replace(tzinfo=UTC)
    return max(0, (clock - first).days)


def finding_summary(db: Session, finding: Finding, *, now: datetime | None = None) -> dict:
    from kestrel.findings.investigation.subject import subject_label_for_list

    subject_label, subject_secondary = subject_label_for_list(db, finding)
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "subject_type": finding.subject_type.value,
        "subject_id": finding.subject_id,
        "subject_label": subject_label,
        "subject_secondary": subject_secondary,
        "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "muted_until": finding.muted_until.isoformat() if finding.muted_until else None,
        "mute_reason": finding.mute_reason,
        "assigned_to": _assigned_to_out(db, finding),
        "policy_version_id": finding.policy_version_id,
        "policy_slug": _policy_slug(db, finding.policy_version_id),
        "age_days": age_days_for(finding, now=now),
    }


def parse_subject_type(raw: str) -> FindingSubjectType:
    try:
        return FindingSubjectType(raw.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(s.value for s in FindingSubjectType)
        raise FindingListError(f"subject_type must be one of: {allowed}") from exc


def apply_finding_filters(
    stmt: Select,
    db: Session,
    org_id: uuid.UUID,
    *,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    assigned_to_operator_id: uuid.UUID | None = None,
    unassigned: bool | None = None,
    open_older_than_days: int | None = None,
    subject_id: uuid.UUID | None = None,
    subject_type: str | None = None,
    application_instance_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> Select:
    """Apply org-scoped list/export filters. Raises FindingListError / FindingInvestigationError."""
    if unassigned and assigned_to_operator_id is not None:
        raise FindingListError("unassigned cannot be combined with assigned_to_operator_id")

    if open_older_than_days is not None:
        if open_older_than_days < 1:
            raise FindingListError("open_older_than_days must be >= 1")
        if status is not None and status.strip().lower() != FindingStatus.OPEN.value:
            raise FindingListError("open_older_than_days only applies to open findings")
        stmt = stmt.where(Finding.status == FindingStatus.OPEN)
        clock = now or datetime.now(UTC)
        cutoff = clock - timedelta(days=open_older_than_days)
        stmt = stmt.where(Finding.first_seen_at <= cutoff)
    elif status:
        stmt = stmt.where(Finding.status == parse_finding_status(status))

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if search:
        stmt = stmt.where(Finding.title.ilike(f"%{search.strip()}%"))
    if policy_version_id:
        stmt = stmt.where(Finding.policy_version_id == policy_version_id)
    if policy_slug:
        slug = policy_slug.strip()
        version_ids = list(
            db.scalars(
                select(PolicyVersion.id)
                .join(Policy, Policy.id == PolicyVersion.policy_id)
                .where(Policy.org_id == org_id, Policy.slug == slug)
            ).all()
        )
        if not version_ids:
            stmt = stmt.where(Finding.id.is_(None))
        else:
            stmt = stmt.where(Finding.policy_version_id.in_(version_ids))
    if unassigned:
        stmt = stmt.where(Finding.assigned_to_operator_id.is_(None))
    elif assigned_to_operator_id:
        stmt = stmt.where(Finding.assigned_to_operator_id == assigned_to_operator_id)

    parsed_subject_type: FindingSubjectType | None = None
    if subject_type is not None and subject_type.strip():
        parsed_subject_type = parse_subject_type(subject_type)
        stmt = stmt.where(Finding.subject_type == parsed_subject_type)
    if subject_id is not None:
        stmt = stmt.where(Finding.subject_id == subject_id)

    if application_instance_id is not None:
        # Findings point at subjects; scope via each subject table's app instance FK.
        identity_ids = select(Identity.id).where(
            Identity.org_id == org_id,
            Identity.application_instance_id == application_instance_id,
        )
        resource_ids = select(Resource.id).where(
            Resource.org_id == org_id,
            Resource.application_instance_id == application_instance_id,
        )
        oauth_ids = select(OAuthApplication.id).where(
            OAuthApplication.org_id == org_id,
            OAuthApplication.application_instance_id == application_instance_id,
        )
        setting_ids = select(TenantSetting.id).where(
            TenantSetting.org_id == org_id,
            TenantSetting.application_instance_id == application_instance_id,
        )
        stmt = stmt.where(
            or_(
                and_(
                    Finding.subject_type == FindingSubjectType.IDENTITY,
                    Finding.subject_id.in_(identity_ids),
                ),
                and_(
                    Finding.subject_type == FindingSubjectType.RESOURCE,
                    Finding.subject_id.in_(resource_ids),
                ),
                and_(
                    Finding.subject_type == FindingSubjectType.OAUTH_APPLICATION,
                    Finding.subject_id.in_(oauth_ids),
                ),
                and_(
                    Finding.subject_type == FindingSubjectType.SETTING,
                    Finding.subject_id.in_(setting_ids),
                ),
            )
        )
    return stmt


def export_findings_for_org(
    db: Session,
    org_id: uuid.UUID,
    *,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    assigned_to_operator_id: uuid.UUID | None = None,
    unassigned: bool | None = None,
    open_older_than_days: int | None = None,
    subject_id: uuid.UUID | None = None,
    subject_type: str | None = None,
    application_instance_id: uuid.UUID | None = None,
    limit: int = EXPORT_FINDINGS_MAX,
    now: datetime | None = None,
) -> list[dict]:
    """Flat export rows (same filters as list), newest last_seen first, capped."""
    cap = min(max(1, limit), EXPORT_FINDINGS_MAX)
    stmt = select(Finding).where(Finding.org_id == org_id)
    stmt = apply_finding_filters(
        stmt,
        db,
        org_id,
        status=status,
        severity=severity,
        search=search,
        policy_version_id=policy_version_id,
        policy_slug=policy_slug,
        assigned_to_operator_id=assigned_to_operator_id,
        unassigned=unassigned,
        open_older_than_days=open_older_than_days,
        subject_id=subject_id,
        subject_type=subject_type,
        application_instance_id=application_instance_id,
        now=now,
    )
    stmt = stmt.order_by(Finding.last_seen_at.desc(), Finding.id.desc()).limit(cap)
    clock = now or datetime.now(UTC)
    return [finding_summary(db, f, now=clock) for f in db.scalars(stmt).all()]


def open_findings_by_age(db: Session, org_id: uuid.UUID, *, now: datetime | None = None) -> dict[str, int]:
    """Count open findings in exclusive age buckets keyed by AGE_BUCKETS labels."""
    clock = now or datetime.now(UTC)
    out = {key: 0 for key, _lo, _hi in AGE_BUCKETS}
    # Age in days via date_part / extract; compare against first_seen_at cutoffs.
    for key, lo, hi in AGE_BUCKETS:
        older = clock - timedelta(days=lo)
        stmt = (
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.OPEN,
                Finding.first_seen_at <= older,
            )
        )
        if hi is not None:
            newer = clock - timedelta(days=hi)
            stmt = stmt.where(Finding.first_seen_at > newer)
        out[key] = int(db.scalar(stmt) or 0)
    return out


def ownership_queues(
    db: Session,
    org_id: uuid.UUID,
    *,
    viewer_operator_id: uuid.UUID | None = None,
) -> dict:
    """SecOps ownership rollup for open findings (unassigned / mine / by assignee)."""
    open_total = int(
        db.scalar(
            select(func.count()).select_from(Finding).where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
        )
        or 0
    )
    open_unassigned = int(
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.OPEN,
                Finding.assigned_to_operator_id.is_(None),
            )
        )
        or 0
    )
    open_assigned_to_me = 0
    if viewer_operator_id is not None:
        open_assigned_to_me = int(
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.org_id == org_id,
                    Finding.status == FindingStatus.OPEN,
                    Finding.assigned_to_operator_id == viewer_operator_id,
                )
            )
            or 0
        )

    by_assignee_rows = db.execute(
        select(Finding.assigned_to_operator_id, func.count())
        .where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.OPEN,
            Finding.assigned_to_operator_id.is_not(None),
        )
        .group_by(Finding.assigned_to_operator_id)
        .order_by(func.count().desc())
    ).all()

    by_assignee: list[dict] = []
    for operator_id, count in by_assignee_rows:
        operator = db.get(Operator, operator_id)
        if operator is None or operator.org_id != org_id:
            continue
        by_assignee.append(
            {
                "operator_id": operator.id,
                "email": operator.email,
                "display_name": operator.display_name,
                "open_count": int(count),
            }
        )

    return {
        "open_total": open_total,
        "open_unassigned": open_unassigned,
        "open_assigned_to_me": open_assigned_to_me,
        "by_assignee": by_assignee,
    }
