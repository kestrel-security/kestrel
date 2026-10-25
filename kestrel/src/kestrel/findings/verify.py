# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding remediation verification re-check.

Re-evaluates the finding's policy against live inventory (same engine as
policy dry-run) for this subject only. Does **not** mutate finding status —
auto-resolve remains sync-driven. Optional sync trigger is handled by the
API layer after this service returns a resolvable connector instance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorInstance
from kestrel.db.models.finding import Finding
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.findings.investigation.subject import _subject_application_instance_id, resolve_subject
from kestrel.policies.dry_run import PolicyDryRunError, dry_run_with_match_keys


class FindingVerifyError(Exception):
    """Raised when verification cannot run (missing policy version, etc.)."""


def resolve_connector_instance_for_finding(db: Session, finding: Finding) -> ConnectorInstance | None:
    """Best-effort connector instance for the finding subject's application."""
    app_instance_id = _subject_application_instance_id(db, finding)
    if app_instance_id is None:
        return None
    return db.scalars(
        select(ConnectorInstance).where(
            ConnectorInstance.org_id == finding.org_id,
            ConnectorInstance.application_instance_id == app_instance_id,
        )
    ).first()


def verify_finding_remediation(db: Session, finding: Finding) -> dict[str, Any]:
    """Dry-run the finding's policy version; classify this subject only."""
    version = db.get(PolicyVersion, finding.policy_version_id)
    if version is None:
        raise FindingVerifyError("Finding references a missing policy version")

    policy = db.get(Policy, version.policy_id)
    if policy is None or policy.org_id != finding.org_id:
        raise FindingVerifyError("Finding references a missing policy")

    from kestrel.findings.toxic_combo import is_system_toxic_policy

    if is_system_toxic_policy(policy):
        return _verify_toxic_combination(db, finding, policy, version)

    subject = resolve_subject(db, finding)
    subject_key = (finding.subject_type.value, str(finding.subject_id))

    try:
        dry, matched_keys = dry_run_with_match_keys(
            db,
            finding.org_id,
            version.source_text,
            policy_id=policy.id,
            policy_slug=policy.slug,
            policy_version_id=version.id,
            match_limit=200,
        )
    except PolicyDryRunError as exc:
        return {
            "as_of": datetime.now(UTC).isoformat(),
            "finding_id": finding.id,
            "result": "policy_error",
            "still_matches": None,
            "would_resolve": None,
            "message": str(exc),
            "errors": list(exc.errors),
            "persisted": False,
            "policy": {
                "id": policy.id,
                "slug": policy.slug,
                "title": policy.title,
                "version": version.version,
                "detail_path": f"/policies/{policy.id}",
            },
            "subject": subject,
            "connector_instance": None,
            "sync_suggested": False,
            "duration_ms": None,
        }

    # The full match set, not the capped `matches` payload: a subject beyond
    # the first `match_limit` matches still matches.
    if subject_key in matched_keys:
        result = "still_matches"
        message = (
            "Policy still matches this subject on live inventory. "
            "Remediation is not reflected yet (or the condition remains true)."
        )
    elif finding.status.value == "open":
        # Open finding absent from matches ⇒ would auto-resolve on next eval.
        result = "would_resolve"
        message = (
            "Subject no longer matches the policy on live inventory. "
            "A successful connector sync + policy evaluation should auto-resolve "
            "this finding (status is not changed by verify)."
        )
    else:
        result = "would_resolve"
        message = (
            "Subject is not matched by the policy on live inventory. "
            "If this finding is still open, re-sync to let reconciliation close it."
        )

    instance = resolve_connector_instance_for_finding(db, finding)
    connector_payload: dict[str, Any] | None = None
    if instance is not None:
        connector_payload = {
            "id": instance.id,
            "application_instance_id": instance.application_instance_id,
            "detail_path": "/connectors",
            "sync_path": f"/connector-instances/{instance.id}/sync",
        }

    return {
        "as_of": datetime.now(UTC).isoformat(),
        "finding_id": finding.id,
        "result": result,
        "still_matches": result == "still_matches",
        "would_resolve": result == "would_resolve",
        "message": message,
        "errors": [],
        "persisted": False,
        "policy": {
            "id": policy.id,
            "slug": policy.slug,
            "title": policy.title,
            "version": version.version,
            "detail_path": f"/policies/{policy.id}",
        },
        "subject": subject,
        "connector_instance": connector_payload,
        "sync_suggested": result == "would_resolve" and connector_payload is not None,
        "duration_ms": dry.get("duration_ms"),
        "dry_run_match_count": dry.get("match_count"),
        "dry_run_would_resolve_count": dry.get("would_resolve_count"),
    }


def _verify_toxic_combination(
    db: Session,
    finding: Finding,
    policy: Policy,
    version: PolicyVersion,
) -> dict[str, Any]:
    """Re-check named toxic combination rules (system policies are not legacy-policy-DSL-eval'd)."""
    from kestrel.findings.toxic_combo import combination_still_matches

    subject = resolve_subject(db, finding)
    still = combination_still_matches(db, finding.org_id, finding)
    if still:
        result = "still_matches"
        message = (
            "Toxic combination still matches on live open findings / inventory signals. "
            "Remediate contributing findings (or revoke sensitive OAuth) then re-check; "
            "status is not changed by verify."
        )
    else:
        result = "would_resolve"
        message = (
            "Toxic combination no longer matches. A successful connector sync + policy "
            "evaluation should auto-resolve this system finding (status is not changed by verify)."
        )

    instance = resolve_connector_instance_for_finding(db, finding)
    connector_payload: dict[str, Any] | None = None
    if instance is not None:
        connector_payload = {
            "id": instance.id,
            "application_instance_id": instance.application_instance_id,
            "detail_path": "/connectors",
            "sync_path": f"/connector-instances/{instance.id}/sync",
        }

    return {
        "as_of": datetime.now(UTC).isoformat(),
        "finding_id": finding.id,
        "result": result,
        "still_matches": result == "still_matches",
        "would_resolve": result == "would_resolve",
        "message": message,
        "errors": [],
        "persisted": False,
        "policy": {
            "id": policy.id,
            "slug": policy.slug,
            "title": policy.title,
            "version": version.version,
            "source": policy.source.value,
            "detail_path": f"/policies/{policy.id}",
        },
        "subject": subject,
        "connector_instance": connector_payload,
        "sync_suggested": result == "would_resolve" and connector_payload is not None,
        "duration_ms": None,
        "dry_run_match_count": None,
        "dry_run_would_resolve_count": None,
    }
