# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Toxic combinations: named attack-path rules over the open findings (and
sensitive OAuth grants) on one subject. ``findings/toxic_combo.py`` turns
each match into a finding.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting

EXPORT_MAX = 5000
SAMPLE_FINDING_LIMIT = 8

# Mirrors kestrel.findings.toxic_combo.SYSTEM_TOXIC_PREFIX (avoid import cycle).
_SYSTEM_TOXIC_PREFIX = "system-toxic-"

# Signal tags derived from policy slug heuristics (and inventory for OAuth).
Signal = str

RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "privileged_no_mfa",
        "title": "Privileged access without MFA",
        "description": "Elevated role or admin grant combined with missing MFA.",
        "required": frozenset({"privileged", "no_mfa"}),
    },
    {
        "id": "privileged_external",
        "title": "External privileged access",
        "description": "Privileged access held by an external / guest identity.",
        "required": frozenset({"privileged", "external"}),
    },
    {
        "id": "disabled_privileged",
        "title": "Disabled account with privileged access",
        "description": "Disabled or deactivated account still holds privileged grants.",
        "required": frozenset({"disabled", "privileged"}),
    },
    {
        "id": "privileged_sensitive_oauth",
        "title": "Privileged identity with sensitive OAuth",
        "description": "Privileged identity also holds an OAuth grant with sensitive scopes.",
        "required": frozenset({"privileged", "sensitive_oauth"}),
    },
    {
        "id": "external_no_mfa",
        "title": "External identity without MFA",
        "description": "External / guest identity lacking MFA.",
        "required": frozenset({"external", "no_mfa"}),
    },
    {
        "id": "cross_app_sensitive_oauth",
        "title": "Cross-app privilege with sensitive OAuth",
        "description": "Cross-application privilege concentration plus sensitive OAuth.",
        "required": frozenset({"cross_app", "sensitive_oauth"}),
    },
)

_RULE_BY_ID = {r["id"]: r for r in RULES}


def _empty_severity_counts() -> dict[str, int]:
    return {s.value: 0 for s in Severity}


def classify_policy_signals(slug: str) -> frozenset[str]:
    """Map a policy slug to attack-path signal tags (explicit heuristics)."""
    slug_l = (slug or "").lower().replace("_", "-")
    tags: set[str] = set()

    if "without-mfa" in slug_l or "no-mfa" in slug_l or "mfa-disabled" in slug_l:
        tags.add("no_mfa")

    if "external" in slug_l or "guest" in slug_l or "collaborator" in slug_l:
        tags.add("external")

    if "disabled" in slug_l or "deactivated" in slug_l or "suspended" in slug_l:
        tags.add("disabled")

    if "cross-app" in slug_l or slug_l.startswith("cross_app"):
        tags.add("cross_app")

    privileged_markers = (
        "admin",
        "privileged",
        "super-admin",
        "owner",
        "org-owner",
        "workspace-owner",
        "help-desk",
        "groups-admin",
    )
    if any(m in slug_l for m in privileged_markers):
        tags.add("privileged")

    if "oauth" in slug_l or "third-party" in slug_l:
        tags.add("sensitive_oauth")

    return frozenset(tags)


def _combo_id(rule_id: str, subject_type: str, subject_id: uuid.UUID) -> str:
    digest = hashlib.sha256(f"{rule_id}:{subject_type}:{subject_id}".encode()).hexdigest()[:16]
    return f"combo_{digest}"


def _subject_label(
    db: Session,
    org_id: uuid.UUID,
    subject_type: FindingSubjectType,
    subject_id: uuid.UUID,
) -> str | None:
    if subject_type == FindingSubjectType.IDENTITY:
        identity = db.scalar(select(Identity).where(Identity.org_id == org_id, Identity.id == subject_id))
        if identity is None:
            return None
        return identity.display_name or identity.email or str(subject_id)
    if subject_type == FindingSubjectType.RESOURCE:
        resource = db.scalar(select(Resource).where(Resource.org_id == org_id, Resource.id == subject_id))
        return resource.name if resource else None
    if subject_type == FindingSubjectType.OAUTH_APPLICATION:
        oauth_app = db.scalar(
            select(OAuthApplication).where(OAuthApplication.org_id == org_id, OAuthApplication.id == subject_id)
        )
        return oauth_app.name if oauth_app else None
    if subject_type == FindingSubjectType.SETTING:
        setting = db.scalar(select(TenantSetting).where(TenantSetting.org_id == org_id, TenantSetting.id == subject_id))
        if setting is None:
            return None
        return setting.label or setting.key
    return None


def _identities_with_sensitive_oauth(db: Session, org_id: uuid.UUID) -> set[uuid.UUID]:
    """Identity ids that hold ≥1 grant whose app has a sensitive scope."""
    sensitive_app_ids = set(
        db.scalars(
            select(OAuthScope.oauth_application_id).where(
                OAuthScope.org_id == org_id,
                OAuthScope.is_sensitive.is_(True),
            )
        ).all()
    )
    if not sensitive_app_ids:
        return set()
    return set(
        db.scalars(
            select(OAuthGrant.identity_id).where(
                OAuthGrant.org_id == org_id,
                OAuthGrant.oauth_application_id.in_(sensitive_app_ids),
            )
        ).all()
    )


def _parse_rule_filter(rule: str | None) -> str | None:
    if rule is None or not str(rule).strip():
        return None
    value = str(rule).strip().lower()
    if value not in _RULE_BY_ID:
        raise ValueError(f"rule must be one of: {', '.join(sorted(_RULE_BY_ID))}")
    return value


def toxic_combinations_report(
    db: Session,
    org_id: uuid.UUID,
    *,
    rule: str | None = None,
    limit: int = EXPORT_MAX,
) -> dict[str, Any]:
    """Subjects matching named toxic combination / attack-path rules."""
    rule_filter = _parse_rule_filter(rule)

    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.org_id == org_id, Finding.status == FindingStatus.OPEN)
            .order_by(Finding.last_seen_at.desc())
        ).all()
    )

    empty = {
        "as_of": datetime.now(UTC).isoformat(),
        "rule": rule_filter,
        "rules": [{"id": r["id"], "title": r["title"], "description": r["description"]} for r in RULES],
        "total_combinations": 0,
        "truncated": False,
        "items": [],
    }
    if not findings:
        return empty

    version_ids = {f.policy_version_id for f in findings}
    versions = {pv.id: pv for pv in db.scalars(select(PolicyVersion).where(PolicyVersion.id.in_(version_ids))).all()}
    policy_ids = {pv.policy_id for pv in versions.values()}
    policies = {p.id: p for p in db.scalars(select(Policy).where(Policy.id.in_(policy_ids))).all()}

    sensitive_oauth_ids = _identities_with_sensitive_oauth(db, org_id)

    # subject_key → findings + accumulated signals + per-signal finding ids
    buckets: dict[str, dict[str, Any]] = {}

    for finding in findings:
        version = versions.get(finding.policy_version_id)
        policy = policies.get(version.policy_id) if version else None
        # system toxic findings must not feed signal classification.
        if policy is not None and (
            policy.source == PolicySource.SYSTEM or (policy.slug or "").startswith(_SYSTEM_TOXIC_PREFIX)
        ):
            continue
        slug = policy.slug if policy else ""
        finding_signals = set(classify_policy_signals(slug))

        key = f"{finding.subject_type.value}:{finding.subject_id}"
        bucket = buckets.setdefault(
            key,
            {
                "subject_type": finding.subject_type,
                "subject_id": finding.subject_id,
                "findings": [],
                "signals": set(),
                "signal_findings": defaultdict(list),
                "policy_slugs": set(),
            },
        )
        bucket["findings"].append(finding)
        if slug:
            bucket["policy_slugs"].add(slug)
        for sig in finding_signals:
            bucket["signals"].add(sig)
            bucket["signal_findings"][sig].append(finding)

    # Inventory signal: sensitive OAuth on identity subjects
    for bucket in buckets.values():
        if bucket["subject_type"] != FindingSubjectType.IDENTITY:
            continue
        if bucket["subject_id"] in sensitive_oauth_ids:
            bucket["signals"].add("sensitive_oauth")

    # Also surface identities that only have sensitive OAuth + would need
    # privileged from findings — already covered when privileged findings exist.
    # Identities with ONLY sensitive OAuth and no open findings are out of scope
    # (no attack-path findings to combine).

    active_rules = [r for r in RULES if rule_filter is None or r["id"] == rule_filter]
    items: list[dict[str, Any]] = []

    for bucket in buckets.values():
        subject_signals: set[str] = bucket["signals"]
        subject_type: FindingSubjectType = bucket["subject_type"]
        subject_id: uuid.UUID = bucket["subject_id"]
        group: list[Finding] = bucket["findings"]

        for rule_def in active_rules:
            required: frozenset[str] = rule_def["required"]
            if not required.issubset(subject_signals):
                continue

            # Contributing findings: those whose signals intersect the rule,
            # or all findings when sensitive_oauth is inventory-only.
            contributing: list[Finding] = []
            seen_ids: set[uuid.UUID] = set()
            rule_finding_signals = required - {"sensitive_oauth"}
            for sig in rule_finding_signals:
                for f in bucket["signal_findings"].get(sig, []):
                    if f.id not in seen_ids:
                        seen_ids.add(f.id)
                        contributing.append(f)
            if not contributing:
                contributing = group[:SAMPLE_FINDING_LIMIT]

            sev = _empty_severity_counts()
            for f in contributing:
                sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

            sample = contributing[:SAMPLE_FINDING_LIMIT]
            sample_ids = [f.id for f in sample]
            primary = sample[0] if sample else group[0]
            label = _subject_label(db, org_id, subject_type, subject_id)

            findings_list_path = f"/findings?status=open&subject_type={subject_type.value}&subject_id={subject_id}"
            investigate_path = f"/investigate?{urlencode({'findings': ','.join(str(i) for i in sample_ids)})}"
            graph_focus_path = f"/graph?focus={subject_id}"
            blast_radius_path = f"/findings/{primary.id}"
            detail_path = None
            if subject_type == FindingSubjectType.IDENTITY:
                detail_path = f"/identities/{subject_id}"
            elif subject_type == FindingSubjectType.OAUTH_APPLICATION:
                detail_path = f"/findings?status=open&subject_id={subject_id}"

            matched_signals = sorted(required)
            items.append(
                {
                    "combination_id": _combo_id(rule_def["id"], subject_type.value, subject_id),
                    "rule_id": rule_def["id"],
                    "rule_title": rule_def["title"],
                    "rule_description": rule_def["description"],
                    "matched_signals": matched_signals,
                    "all_signals": sorted(subject_signals),
                    "subject_type": subject_type.value,
                    "subject_id": subject_id,
                    "label": label or str(subject_id),
                    "finding_count": len(contributing),
                    "open_by_severity": sev,
                    "sample_finding_ids": sample_ids,
                    "sample_policy_slugs": sorted(bucket["policy_slugs"])[:SAMPLE_FINDING_LIMIT],
                    "findings_list_path": findings_list_path,
                    "investigate_path": investigate_path,
                    "graph_focus_path": graph_focus_path,
                    "blast_radius_path": blast_radius_path,
                    "detail_path": detail_path,
                    "finding_id": None,  # filled below when a system finding exists
                    "finding_path": None,
                }
            )

    # Prefer more matched signals, then higher finding count, then label.
    items.sort(
        key=lambda row: (
            -len(row["matched_signals"]),
            -int(row["finding_count"]),
            str(row["rule_id"]),
            str(row["label"]).lower(),
        )
    )
    truncated = False
    if len(items) > limit:
        items = items[:limit]
        truncated = True

    _attach_persisted_finding_ids(db, org_id, items)

    return {
        "as_of": datetime.now(UTC).isoformat(),
        "rule": rule_filter,
        "rules": [{"id": r["id"], "title": r["title"], "description": r["description"]} for r in RULES],
        "total_combinations": len(items),
        "truncated": truncated,
        "items": items,
    }


def _attach_persisted_finding_ids(db: Session, org_id: uuid.UUID, items: list[dict[str, Any]]) -> None:
    """Link report rows to open system toxic findings when present."""
    if not items:
        return
    # Lazy import avoids cycle with findings.toxic_combo → this module.
    from kestrel.findings.toxic_combo import finding_id_for_combination

    for item in items:
        subject_id = item["subject_id"]
        if not isinstance(subject_id, uuid.UUID):
            subject_id = uuid.UUID(str(subject_id))
        fid = finding_id_for_combination(
            db,
            org_id,
            rule_id=item["rule_id"],
            subject_type=item["subject_type"],
            subject_id=subject_id,
        )
        if fid is not None:
            item["finding_id"] = fid
            item["finding_path"] = f"/findings/{fid}"
            # Prefer the persisted combo finding for blast-radius deep-link.
            item["blast_radius_path"] = f"/findings/{fid}"


def toxic_combination_count(db: Session, org_id: uuid.UUID) -> int:
    """Dashboard rollup: number of matching toxic combinations."""
    report = toxic_combinations_report(db, org_id, limit=EXPORT_MAX)
    return int(report["total_combinations"])
