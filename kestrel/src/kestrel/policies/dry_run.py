# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Python policy dry-run against live inventory.

Evaluates policies against the org's current normalized data without
persisting PolicyEvaluation rows or reconciling Findings.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.resource import Resource
from kestrel.policies.runtime import PolicyCompileError, get_default_runtime

MATCH_CAP = 200


class PolicyDryRunError(Exception):
    """Raised when dry-run cannot evaluate (compile/runtime)."""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or [message]


def _subject_label(
    db: Session,
    org_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
) -> dict[str, Any]:
    """Best-effort label for a match subject."""
    base: dict[str, Any] = {
        "subject_type": subject_type,
        "subject_id": subject_id,
        "label": None,
        "detail_path": None,
        "secondary": None,
        "findings_list_path": (f"/findings?status=open&subject_type={subject_type}&subject_id={subject_id}"),
    }
    if subject_type == FindingSubjectType.IDENTITY.value:
        identity = db.get(Identity, subject_id)
        if identity is not None and identity.org_id == org_id:
            base["label"] = identity.display_name or identity.email or identity.provider_object_id
            base["secondary"] = identity.email
        return base
    if subject_type == FindingSubjectType.RESOURCE.value:
        resource = db.get(Resource, subject_id)
        if resource is not None and resource.org_id == org_id:
            base["label"] = resource.name
            base["secondary"] = (
                resource.resource_type.value if hasattr(resource.resource_type, "value") else str(resource.resource_type)
            )
        return base
    if subject_type == FindingSubjectType.OAUTH_APPLICATION.value:
        app = db.get(OAuthApplication, subject_id)
        if app is not None and app.org_id == org_id:
            base["label"] = app.name
        return base
    return base


def _unresolved_findings_for_policy(
    db: Session,
    org_id: uuid.UUID,
    *,
    policy_id: uuid.UUID | None,
    policy_version_id: uuid.UUID | None,
) -> dict[tuple[str, str], Finding]:
    """Non-resolved findings per subject, the set evaluation reconciles
    against. Keyed by policy, not version, so with ``policy_id`` this spans
    every version of it. Later rows win, matching "latest per subject"."""
    if policy_id is not None:
        scope = PolicyVersion.policy_id == policy_id
    elif policy_version_id is not None:
        scope = Finding.policy_version_id == policy_version_id
    else:
        return {}
    rows = db.scalars(
        select(Finding)
        .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
        .where(Finding.org_id == org_id, scope, Finding.status != FindingStatus.RESOLVED)
        .order_by(Finding.first_seen_at, Finding.id)
    ).all()
    return {(f.subject_type.value, str(f.subject_id)): f for f in rows}


def dry_run_source_text(
    db: Session,
    org_id: uuid.UUID,
    source_text: str,
    *,
    policy_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    match_limit: int = MATCH_CAP,
) -> dict:
    """Compile source_text then dry-run against live inventory."""
    payload, _ = dry_run_with_match_keys(
        db,
        org_id,
        source_text,
        policy_id=policy_id,
        policy_slug=policy_slug,
        policy_version_id=policy_version_id,
        match_limit=match_limit,
    )
    return payload


def dry_run_with_match_keys(
    db: Session,
    org_id: uuid.UUID,
    source_text: str,
    *,
    policy_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    match_limit: int = MATCH_CAP,
) -> tuple[dict, set[tuple[str, str]]]:
    """``dry_run_source_text`` plus every matched ``(subject_type, subject_id)``.

    ``match_limit`` caps only the returned ``matches`` / ``would_resolve``
    lists. The counts, and whether an open finding would resolve, use the full
    match set: a subject past the cap still matches.
    """
    runtime = get_default_runtime()
    try:
        compiled = runtime.compile(source_text)
    except PolicyCompileError as exc:
        raise PolicyDryRunError(f"Compile failed: {exc}", errors=[str(exc)]) from exc

    limit = max(1, min(match_limit, MATCH_CAP))
    started = time.monotonic()
    try:
        result = runtime.evaluate_all(compiled, db, org_id)
    except Exception as exc:
        raise PolicyDryRunError(f"Evaluation failed: {exc}") from exc

    existing_by_subject = _unresolved_findings_for_policy(
        db, org_id, policy_id=policy_id, policy_version_id=policy_version_id
    )
    matched_keys: set[tuple[str, str]] = {(m.subject_type, str(m.subject_id)) for m in result.matches}
    matches: list[dict] = []
    truncated = len(result.matches) > limit

    for match in result.matches[:limit]:
        key = (match.subject_type, str(match.subject_id))
        existing = existing_by_subject.get(key)
        subject = _subject_label(db, org_id, match.subject_type, match.subject_id)
        matches.append(
            {
                **subject,
                "evidence": match.evidence,
                "match_status": "existing" if existing is not None else "new",
                "existing_finding_id": existing.id if existing is not None else None,
                "existing_finding_path": (f"/findings/{existing.id}" if existing is not None else None),
            }
        )

    # Only open findings auto-resolve; triaged ones keep their status.
    resolving = [
        (key, finding)
        for key, finding in existing_by_subject.items()
        if key not in matched_keys and finding.status == FindingStatus.OPEN
    ]
    would_resolve: list[dict] = []
    for key, finding in resolving[:limit]:
        subject_type, subject_id_str = key
        subject = _subject_label(db, org_id, subject_type, uuid.UUID(subject_id_str))
        would_resolve.append(
            {
                **subject,
                "existing_finding_id": finding.id,
                "existing_finding_path": f"/findings/{finding.id}",
                "match_status": "would_resolve",
            }
        )

    existing_count = sum(1 for key in matched_keys if key in existing_by_subject)
    new_count = len(matched_keys) - existing_count

    payload = {
        "as_of": datetime.now(UTC).isoformat(),
        "dry_run": True,
        "persisted": False,
        "policy_id": policy_id,
        "policy_slug": policy_slug or compiled.contract.policy_id,
        "policy_version_id": policy_version_id,
        "severity": compiled.contract.severity,
        "evaluated_row_count": result.evaluated_row_count,
        "match_count": len(result.matches),
        "truncated": truncated,
        "match_limit": limit,
        "new_match_count": new_count,
        "existing_match_count": existing_count,
        "would_resolve_count": len(resolving),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "matches": matches,
        "would_resolve": would_resolve,
    }
    return payload, matched_keys


def dry_run_policy(
    db: Session,
    org_id: uuid.UUID,
    policy: Policy,
    *,
    source_text: str | None = None,
    match_limit: int = MATCH_CAP,
) -> dict:
    """Dry-run a saved policy's current version, or an optional draft source."""
    version: PolicyVersion | None = None
    if policy.current_version_id is not None:
        version = db.get(PolicyVersion, policy.current_version_id)

    if source_text is not None:
        return dry_run_source_text(
            db,
            org_id,
            source_text,
            policy_id=policy.id,
            policy_slug=policy.slug,
            policy_version_id=version.id if version is not None else None,
            match_limit=match_limit,
        )

    if version is None:
        raise PolicyDryRunError("Policy has no current version to evaluate")

    return dry_run_source_text(
        db,
        org_id,
        version.source_text,
        policy_id=policy.id,
        policy_slug=policy.slug,
        policy_version_id=version.id,
        match_limit=match_limit,
    )
