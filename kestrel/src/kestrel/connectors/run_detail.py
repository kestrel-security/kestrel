# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector sync run detail.

Enriches a single ``ConnectorRun`` with instance/application context and
policy evaluations fired for that run — the operator drill-down missing
from the connectors list / inventory recent-runs tables.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.connectors.run_drift import previous_successful_run, run_change_summary
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.connector import Connector, ConnectorInstance, ConnectorRun
from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicyVersion


def _duration_seconds(run: ConnectorRun) -> float | None:
    if run.started_at is None or run.finished_at is None:
        return None
    return max(0.0, (run.finished_at - run.started_at).total_seconds())


# Coarse failure classes a connector records for a family it could not read,
# mapped to what an operator should do about it.
_SKIP_REASONS: dict[str, str] = {
    "permission": "The credential cannot read this family. Grant the scope or permission named in the setup guide.",
    "authentication": "The credential was rejected. Re-authenticate the connector.",
    "rate_limit": "The provider throttled this family. It will be retried on the next run.",
    "not_configured": "The provider has nothing to return here — the feature is not set up in that tenant.",
    "network": "The provider was unreachable while reading this family.",
}


def _coverage(run: ConnectorRun, object_counts: dict[str, Any]) -> dict[str, Any]:
    """What this run actually read, and what it could not.

    Reduced coverage used to be a sentence inside ``error_summary``, which put
    "we could not read your audit log" in the same field as a stack trace. This
    separates the two: collected families with their counts, skipped families
    with a reason and what to do about it.
    """
    skipped = [
        {
            "object_type": family,
            "reason": reason,
            "detail": _SKIP_REASONS.get(str(reason), "This family was not collected on this run."),
        }
        for family, reason in sorted((run.skipped_object_types or {}).items())
    ]
    return {
        "collected": [
            {"object_type": name, "count": int(count)}
            for name, count in sorted(object_counts.items())
            if isinstance(count, (int, float))
        ],
        "skipped": skipped,
        "is_complete": not skipped and run.status.value == "success",
        "notice": run.error_summary if run.status.value == "partial_failure" else None,
    }


def connector_run_detail(
    db: Session,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
) -> dict[str, Any] | None:
    """Org-scoped sync run detail, or ``None`` if missing / wrong tenant."""
    run = db.get(ConnectorRun, run_id)
    if run is None or run.org_id != org_id:
        return None

    instance = db.get(ConnectorInstance, run.connector_instance_id)
    if instance is None or instance.org_id != org_id:
        return None

    connector = db.get(Connector, instance.connector_id)
    app_instance = db.get(ApplicationInstance, instance.application_instance_id)
    application = db.get(Application, app_instance.application_id) if app_instance is not None else None

    evaluations = list(
        db.execute(
            select(PolicyEvaluation, PolicyVersion, Policy)
            .join(PolicyVersion, PolicyVersion.id == PolicyEvaluation.policy_version_id)
            .join(Policy, Policy.id == PolicyVersion.policy_id)
            .where(
                PolicyEvaluation.org_id == org_id,
                PolicyEvaluation.connector_run_id == run.id,
            )
            .order_by(Policy.slug)
        ).all()
    )

    object_counts = run.object_counts or {}
    objects_total = sum(int(v) for v in object_counts.values() if isinstance(v, (int, float)))
    coverage = _coverage(run, object_counts)
    change_summary = run_change_summary(db, org_id, run.id)
    prev = previous_successful_run(
        db,
        org_id,
        connector_instance_id=instance.id,
        before_run=run,
    )
    previous_run: dict[str, Any] | None = None
    if prev is not None:
        previous_run = {
            "id": prev.id,
            "status": prev.status.value,
            "started_at": prev.started_at.isoformat() if prev.started_at else None,
            "finished_at": prev.finished_at.isoformat() if prev.finished_at else None,
            "detail_path": f"/connectors/runs/{prev.id}",
            "change_summary": run_change_summary(db, org_id, prev.id),
        }

    return {
        "id": run.id,
        "status": run.status.value,
        "triggered_by": run.triggered_by.value,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_seconds": _duration_seconds(run),
        "object_counts": object_counts,
        "objects_total": objects_total,
        "coverage": coverage,
        "error_summary": run.error_summary,
        "change_summary": change_summary,
        "previous_successful_run": previous_run,
        "changes_path": f"/connectors/runs/{run.id}#drift",
        "connector_instance": {
            "id": instance.id,
            "auth_method": instance.auth_method.value,
            "sync_mode": instance.sync_mode.value,
            "schedule_cron": instance.schedule_cron,
            "connector_id": instance.connector_id,
            "connector_name": connector.name if connector else None,
            "connector_display_name": ((connector.manifest or {}).get("display_name") if connector else None),
            "detail_path": "/connectors",
        },
        "application": {
            "id": app_instance.id if app_instance else None,
            "display_name": app_instance.display_name if app_instance else None,
            "application_type": application.application_type.value if application else None,
            "detail_path": None,
        },
        "policy_evaluations": [
            {
                "id": evaluation.id,
                "status": evaluation.status.value,
                "matched_object_count": evaluation.matched_object_count,
                "error_message": evaluation.error_message,
                "started_at": evaluation.started_at.isoformat() if evaluation.started_at else None,
                "finished_at": evaluation.finished_at.isoformat() if evaluation.finished_at else None,
                "policy_id": policy.id,
                "policy_slug": policy.slug,
                "policy_title": policy.title,
                "policy_version": version.version,
                "severity": version.severity.value,
                "policy_detail_path": f"/policies/{policy.id}",
                "findings_list_path": f"/findings?policy_slug={policy.slug}",
            }
            for evaluation, version, policy in evaluations
        ],
        "policy_evaluation_count": len(evaluations),
    }
