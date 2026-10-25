# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Persist toxic combination matches as first-class findings.

Ensures org-scoped ``PolicySource.SYSTEM`` policies for each named rule in
``kestrel.reports.toxic_combinations``, then reconciles open findings after
normal policy evaluation — create / refresh / auto-resolve with evidence
linking contributing findings. System toxic findings are excluded from the
combo report signal scan so they cannot feed back into themselves.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.findings.pipeline import _reconcile_findings
from kestrel.policies.runtime import PolicyEvaluationResult, PolicyMatch
from kestrel.reports.toxic_combinations import RULES, toxic_combinations_report

SYSTEM_TOXIC_PREFIX = "system-toxic-"
SYSTEM_PACK_NAME = "kestrel-system"

# rule_id → severity for persisted combo findings
_RULE_SEVERITY: dict[str, Severity] = {
    "privileged_no_mfa": Severity.CRITICAL,
    "privileged_external": Severity.HIGH,
    "disabled_privileged": Severity.CRITICAL,
    "privileged_sensitive_oauth": Severity.HIGH,
    "external_no_mfa": Severity.MEDIUM,
    "cross_app_sensitive_oauth": Severity.HIGH,
}

_RULE_REMEDIATION: dict[str, str] = {
    "privileged_no_mfa": (
        "Enforce MFA on the privileged identity, or remove elevated roles until MFA is enabled. "
        "Investigate contributing findings linked in evidence."
    ),
    "privileged_external": (
        "Review external / guest privileged access; remove elevated roles or convert to a "
        "managed identity with stronger controls."
    ),
    "disabled_privileged": ("Revoke privileged grants on the disabled account immediately, then confirm offboarding."),
    "privileged_sensitive_oauth": (
        "Review sensitive OAuth grants on the privileged identity; revoke unused or over-scoped apps."
    ),
    "external_no_mfa": ("Require MFA for external identities or remove access until MFA is confirmed."),
    "cross_app_sensitive_oauth": (
        "Reduce cross-app privilege concentration and revoke sensitive OAuth grants that are not required."
    ),
}


def system_toxic_slug(rule_id: str) -> str:
    """Stable policy slug for a toxic combination rule."""
    return f"{SYSTEM_TOXIC_PREFIX}{rule_id.replace('_', '-')}"


def is_system_toxic_slug(slug: str | None) -> bool:
    return bool(slug) and str(slug).startswith(SYSTEM_TOXIC_PREFIX)


def rule_id_from_system_slug(slug: str) -> str | None:
    if not is_system_toxic_slug(slug):
        return None
    return str(slug)[len(SYSTEM_TOXIC_PREFIX) :].replace("-", "_")


def is_system_toxic_policy(policy: Policy | None) -> bool:
    if policy is None:
        return False
    return policy.source == PolicySource.SYSTEM and is_system_toxic_slug(policy.slug)


def ensure_system_toxic_policies(session: Session, org_id: uuid.UUID) -> dict[str, PolicyVersion]:
    """Create missing system toxic policies for the org; return rule_id → version."""
    by_rule: dict[str, PolicyVersion] = {}
    for rule in RULES:
        rule_id: str = rule["id"]
        slug = system_toxic_slug(rule_id)
        policy = session.scalar(select(Policy).where(Policy.org_id == org_id, Policy.slug == slug))
        severity = _RULE_SEVERITY.get(rule_id, Severity.HIGH)
        remediation = _RULE_REMEDIATION.get(rule_id, rule["description"])
        source_text = _system_source_text(
            slug=slug,
            title=rule["title"],
            description=rule["description"],
            severity=severity,
            remediation=remediation,
        )

        if policy is None:
            policy = Policy(
                id=uuid.uuid4(),
                org_id=org_id,
                slug=slug,
                title=rule["title"],
                description=rule["description"],
                source=PolicySource.SYSTEM,
                pack_name=SYSTEM_PACK_NAME,
            )
            session.add(policy)
            session.flush()
            new_version = PolicyVersion(
                id=uuid.uuid4(),
                policy_id=policy.id,
                version=1,
                source_text=source_text,
                severity=severity,
                remediation=remediation,
                compliance_mappings={},
                is_enabled=True,
                created_by="system",
            )
            session.add(new_version)
            session.flush()
            policy.current_version_id = new_version.id
            by_rule[rule_id] = new_version
            continue

        policy.title = rule["title"]
        policy.description = rule["description"]
        policy.source = PolicySource.SYSTEM
        policy.pack_name = SYSTEM_PACK_NAME

        current: PolicyVersion | None = None
        if policy.current_version_id is not None:
            current = session.get(PolicyVersion, policy.current_version_id)
        if current is None:
            current = PolicyVersion(
                id=uuid.uuid4(),
                policy_id=policy.id,
                version=1,
                source_text=source_text,
                severity=severity,
                remediation=remediation,
                compliance_mappings={},
                is_enabled=True,
                created_by="system",
            )
            session.add(current)
            session.flush()
            policy.current_version_id = current.id
        else:
            current.source_text = source_text
            current.severity = severity
            current.remediation = remediation
            current.is_enabled = True

        by_rule[rule_id] = current

    session.flush()
    return by_rule


def _system_source_text(
    *,
    slug: str,
    title: str,
    description: str,
    severity: Severity,
    remediation: str,
) -> str:
    """A valid policy that never matches. It exists so toxic-combination
    findings have a policy to belong to; their matches come from
    ``reconcile_toxic_combination_findings``, not from evaluating this."""
    return (
        f"POLICY_ID = {slug!r}\n"
        f"TITLE = {title!r}\n"
        f"SEVERITY = {severity.value!r}\n"
        'RESOURCE_TYPE = "identity"\n'
        f"DESCRIPTION = {description!r}\n"
        f"REMEDIATION = {remediation!r}\n"
        "\n"
        "\n"
        "def policy(resource):\n"
        '    """System toxic combination: findings are reconciled from contributing findings."""\n'
        "    return True\n"
    )


def reconcile_toxic_combination_findings(
    session: Session,
    org_id: uuid.UUID,
    connector_run_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> list[PolicyEvaluation]:
    """Open / refresh / resolve system findings for current toxic combinations."""
    versions_by_rule = ensure_system_toxic_policies(session, org_id)
    report = toxic_combinations_report(session, org_id)
    items_by_rule: dict[str, list[dict[str, Any]]] = {r["id"]: [] for r in RULES}
    for item in report["items"]:
        items_by_rule.setdefault(item["rule_id"], []).append(item)

    evaluations: list[PolicyEvaluation] = []
    now = datetime.now(UTC)

    for rule in RULES:
        rule_id: str = rule["id"]
        version = versions_by_rule[rule_id]
        items = items_by_rule.get(rule_id, [])

        evaluation = PolicyEvaluation(
            id=uuid.uuid4(),
            org_id=org_id,
            policy_version_id=version.id,
            connector_run_id=connector_run_id,
            started_at=now,
            status=PolicyEvaluationStatus.SUCCESS,
            matched_object_count=len(items),
            finished_at=now,
        )
        session.add(evaluation)
        session.flush()
        evaluations.append(evaluation)

        matches: list[PolicyMatch] = []
        for item in items:
            subject_id = item["subject_id"]
            if not isinstance(subject_id, uuid.UUID):
                subject_id = uuid.UUID(str(subject_id))
            evidence = {
                "rule_id": item["rule_id"],
                "combination_id": item["combination_id"],
                "matched_signals": list(item.get("matched_signals") or []),
                "all_signals": list(item.get("all_signals") or []),
                "contributing_finding_ids": [str(i) for i in (item.get("sample_finding_ids") or [])],
                "sample_policy_slugs": list(item.get("sample_policy_slugs") or []),
                "rule_title": item.get("rule_title"),
                "rule_description": item.get("rule_description"),
                "label": item.get("label"),
            }
            matches.append(
                PolicyMatch(
                    subject_type=item["subject_type"],
                    subject_id=subject_id,
                    evidence=evidence,
                )
            )

        result = PolicyEvaluationResult(policy_name=rule["title"], matches=matches)
        _reconcile_findings(
            session,
            org_id,
            version,
            evaluation,
            result,
            webhook_delivery_ids=webhook_delivery_ids,
        )

        for finding in session.scalars(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.policy_version_id == version.id,
                Finding.status == FindingStatus.OPEN,
            )
        ).all():
            finding.title = rule["title"]

    return evaluations


def finding_id_for_combination(
    session: Session,
    org_id: uuid.UUID,
    *,
    rule_id: str,
    subject_type: str,
    subject_id: uuid.UUID,
) -> uuid.UUID | None:
    """Lookup open system finding for a toxic combination key, if persisted."""
    slug = system_toxic_slug(rule_id)
    policy = session.scalar(select(Policy).where(Policy.org_id == org_id, Policy.slug == slug))
    if policy is None or policy.current_version_id is None:
        return None

    finding = session.scalar(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.policy_version_id == policy.current_version_id,
            Finding.subject_type == FindingSubjectType(subject_type),
            Finding.subject_id == subject_id,
            Finding.status == FindingStatus.OPEN,
        )
    )
    return finding.id if finding else None


def combination_still_matches(session: Session, org_id: uuid.UUID, finding: Finding) -> bool:
    """Whether the finding's toxic rule still matches its subject (for verify)."""
    version = session.get(PolicyVersion, finding.policy_version_id)
    if version is None:
        return False
    policy = session.get(Policy, version.policy_id)
    if not is_system_toxic_policy(policy) or policy is None:
        return False
    rule_id = rule_id_from_system_slug(policy.slug)
    if rule_id is None:
        return False
    report = toxic_combinations_report(session, org_id, rule=rule_id)
    subject_key = (finding.subject_type.value, str(finding.subject_id))
    return any((item["subject_type"], str(item["subject_id"])) == subject_key for item in report["items"])
