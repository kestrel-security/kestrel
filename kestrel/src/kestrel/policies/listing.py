# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy list summaries with open-finding counts and last evaluation.

Also provides the policy-detail open-findings strip payload.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicyVersion, Severity
from kestrel.findings.investigation.subject import resolve_subject

# Prefer a lightweight parse of source_text over RestrictedPython compile/eval.
_RESOURCE_TYPE_RE = re.compile(
    r"""^\s*RESOURCE_TYPE\s*=\s*(['"])(?P<value>[^'"]+)\1""",
    re.MULTILINE,
)

DEFAULT_OPEN_FINDINGS_LIMIT = 20
MAX_OPEN_FINDINGS_LIMIT = 100


def extract_resource_type(source_text: str | None) -> str | None:
    """Return RESOURCE_TYPE string literal from policy source, or None."""
    if not source_text:
        return None
    match = _RESOURCE_TYPE_RE.search(source_text)
    return match.group("value") if match else None


def _empty_severity_counts() -> dict[str, int]:
    return {s.value: 0 for s in Severity}


def _open_finding_counts(session: Session, org_id: uuid.UUID, policy_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not policy_ids:
        return {}
    rows = session.execute(
        select(PolicyVersion.policy_id, func.count())
        .select_from(Finding)
        .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
        .where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.OPEN,
            PolicyVersion.policy_id.in_(policy_ids),
        )
        .group_by(PolicyVersion.policy_id)
    ).all()
    return {policy_id: int(count) for policy_id, count in rows}


def _open_finding_severity_counts(session: Session, org_id: uuid.UUID, policy_id: uuid.UUID) -> dict[str, int]:
    """Org-scoped open finding counts by severity for one policy (all versions)."""
    out = _empty_severity_counts()
    rows = session.execute(
        select(Finding.severity, func.count())
        .select_from(Finding)
        .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
        .where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.OPEN,
            PolicyVersion.policy_id == policy_id,
        )
        .group_by(Finding.severity)
    ).all()
    for severity, count in rows:
        out[severity.value] = int(count)
    return out


def _has_evaluations(session: Session, org_id: uuid.UUID, policy_id: uuid.UUID) -> bool:
    """True when any PolicyEvaluation exists for this policy (org-scoped)."""
    row = session.execute(
        select(PolicyEvaluation.id)
        .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
        .where(
            PolicyEvaluation.org_id == org_id,
            PolicyVersion.policy_id == policy_id,
        )
        .limit(1)
    ).first()
    return row is not None


def _last_evaluations(
    session: Session, org_id: uuid.UUID, policy_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, str | None]]:
    """Map policy_id -> (status, last_evaluated_at iso). Newest started_at wins."""
    if not policy_ids:
        return {}
    # DISTINCT ON (PostgreSQL): one row per policy, newest evaluation first.
    rows = session.execute(
        select(
            PolicyVersion.policy_id,
            PolicyEvaluation.status,
            PolicyEvaluation.finished_at,
            PolicyEvaluation.started_at,
        )
        .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
        .where(
            PolicyEvaluation.org_id == org_id,
            PolicyVersion.policy_id.in_(policy_ids),
        )
        .distinct(PolicyVersion.policy_id)
        .order_by(PolicyVersion.policy_id, PolicyEvaluation.started_at.desc())
    ).all()

    out: dict[uuid.UUID, tuple[str, str | None]] = {}
    for policy_id, status, finished_at, started_at in rows:
        when = finished_at or started_at
        out[policy_id] = (
            status.value,
            when.isoformat() if when is not None else None,
        )
    return out


def policy_summary_dict(
    policy: Policy,
    version: PolicyVersion | None,
    *,
    open_finding_count: int = 0,
    last_evaluation_status: str | None = None,
    last_evaluated_at: str | None = None,
) -> dict[str, Any]:
    """Serialize a policy list/detail summary row."""
    return {
        "id": policy.id,
        "slug": policy.slug,
        "title": policy.title,
        "source": policy.source.value,
        "pack_name": policy.pack_name,
        "application": _application_for_pack_name(policy.pack_name),
        "current_version_id": policy.current_version_id,
        "version": version.version if version else None,
        "severity": version.severity.value if version else None,
        "is_enabled": version.is_enabled if version else None,
        "resource_type": extract_resource_type(version.source_text if version else None),
        "open_finding_count": open_finding_count,
        "last_evaluation_status": last_evaluation_status,
        "last_evaluated_at": last_evaluated_at,
    }


_PACK_APPLICATION: dict[str, str] = {
    "github-posture": "github",
    "okta-posture": "okta",
    "gws-posture": "google_workspace",
    "slack-posture": "slack",
    "cross-app": "cross_app",
}


def _application_for_pack_name(pack_name: str | None) -> str | None:
    if not pack_name:
        return None
    return _PACK_APPLICATION.get(pack_name)


def list_policy_summaries(session: Session, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Org-scoped policy list with batched open counts and last evaluation."""
    policies = list(session.scalars(select(Policy).where(Policy.org_id == org_id).order_by(Policy.slug)).all())
    if not policies:
        return []

    policy_ids = [p.id for p in policies]
    version_ids = [p.current_version_id for p in policies if p.current_version_id]
    versions_by_id: dict[uuid.UUID, PolicyVersion] = {}
    if version_ids:
        for policy_version in session.scalars(select(PolicyVersion).where(PolicyVersion.id.in_(version_ids))).all():
            versions_by_id[policy_version.id] = policy_version

    open_counts = _open_finding_counts(session, org_id, policy_ids)
    last_evals = _last_evaluations(session, org_id, policy_ids)

    out: list[dict[str, Any]] = []
    for policy in policies:
        version = versions_by_id.get(policy.current_version_id) if policy.current_version_id else None
        status, evaluated_at = last_evals.get(policy.id, (None, None))
        out.append(
            policy_summary_dict(
                policy,
                version,
                open_finding_count=open_counts.get(policy.id, 0),
                last_evaluation_status=status,
                last_evaluated_at=evaluated_at,
            )
        )
    return out


def enrich_policy_summary(
    session: Session, org_id: uuid.UUID, policy: Policy, version: PolicyVersion | None
) -> dict[str, Any]:
    """Single-policy summary with open count + last eval (detail/create/patch)."""
    open_counts = _open_finding_counts(session, org_id, [policy.id])
    last_evals = _last_evaluations(session, org_id, [policy.id])
    status, evaluated_at = last_evals.get(policy.id, (None, None))
    return policy_summary_dict(
        policy,
        version,
        open_finding_count=open_counts.get(policy.id, 0),
        last_evaluation_status=status,
        last_evaluated_at=evaluated_at,
    )


def policy_open_findings(
    session: Session,
    org_id: uuid.UUID,
    policy: Policy,
    *,
    limit: int = DEFAULT_OPEN_FINDINGS_LIMIT,
) -> dict[str, Any]:
    """Open findings strip for policy detail.

    Distinguishes never-evaluated (no PolicyEvaluation rows) from evaluated
    with zero open findings via ``ever_evaluated``. Counts reuse the same
    org-scoped open-finding join as list enrichment.
    """
    capped = max(1, min(int(limit), MAX_OPEN_FINDINGS_LIMIT))
    open_counts = _open_finding_counts(session, org_id, [policy.id])
    open_count = open_counts.get(policy.id, 0)
    open_by_severity = _open_finding_severity_counts(session, org_id, policy.id)
    ever_evaluated = _has_evaluations(session, org_id, policy.id)

    findings = list(
        session.scalars(
            select(Finding)
            .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
            .where(
                Finding.org_id == org_id,
                Finding.status == FindingStatus.OPEN,
                PolicyVersion.policy_id == policy.id,
            )
            .order_by(Finding.last_seen_at.desc(), Finding.id.desc())
            .limit(capped)
        ).all()
    )

    items: list[dict[str, Any]] = []
    for finding in findings:
        subject = resolve_subject(session, finding)
        items.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "subject_type": finding.subject_type.value,
                "subject_id": finding.subject_id,
                "subject_label": subject.get("label"),
                "last_seen_at": finding.last_seen_at.isoformat(),
                "detail_path": f"/findings/{finding.id}",
            }
        )

    return {
        "policy_id": policy.id,
        "policy_slug": policy.slug,
        "ever_evaluated": ever_evaluated,
        "open_finding_count": open_count,
        "open_by_severity": open_by_severity,
        "open_findings": items,
        "open_findings_truncated": open_count > len(items),
        "limit": capped,
        "findings_list_path": f"/findings?policy_slug={policy.slug}",
    }
