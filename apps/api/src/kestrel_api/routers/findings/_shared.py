# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the findings sub-routers.

`_apply_finding_patch` is the one status/assignment write path behind both
`PATCH /findings/{id}` and `POST /findings/bulk`, so the two stay in lockstep
(same validation, audit row, webhooks and notifications).
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED
from kestrel.findings.investigation.status import FindingInvestigationError, apply_status_transition, parse_finding_status
from kestrel.findings.listing import finding_summary
from kestrel.notifications.dispatch import schedule_finding_notifications
from kestrel.webhooks.dispatch import schedule_finding_webhooks
from sqlalchemy.orm import Session

_EXPORT_FORMATS = frozenset({"csv", "json"})


def _summary(db: Session, f: Finding) -> dict:
    return finding_summary(db, f)


def _apply_finding_patch(
    db: Session,
    *,
    finding: Finding,
    org: Organization,
    actor: Operator,
    status: str | None,
    assign_set: bool,
    assigned_to_operator_id: uuid.UUID | None,
    webhook_delivery_ids: list,
) -> dict:
    """Mutate one finding; returns the audit `changes` dict (possibly empty)."""
    changes: dict = {}
    previous_status = finding.status
    if status is not None:
        try:
            new_status = parse_finding_status(status)
        except FindingInvestigationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if new_status == FindingStatus.MUTED:
            raise HTTPException(
                status_code=422,
                detail="use POST /findings/{id}/mute to mute with a required expiry",
            )
        apply_status_transition(finding, new_status)
        changes["status"] = new_status.value
        changes["resolved_at"] = finding.resolved_at.isoformat() if finding.resolved_at else None
        changes["muted_until"] = None
        if previous_status != new_status:
            if new_status == FindingStatus.OPEN:
                schedule_finding_webhooks(
                    db,
                    org_id=org.id,
                    event_type=FINDING_OPENED,
                    finding=finding,
                    delivery_ids=webhook_delivery_ids,
                )
                schedule_finding_notifications(
                    db,
                    org_id=org.id,
                    event_type=FINDING_OPENED,
                    finding=finding,
                )
            elif new_status == FindingStatus.RESOLVED:
                schedule_finding_webhooks(
                    db,
                    org_id=org.id,
                    event_type=FINDING_RESOLVED,
                    finding=finding,
                    delivery_ids=webhook_delivery_ids,
                )
                schedule_finding_notifications(
                    db,
                    org_id=org.id,
                    event_type=FINDING_RESOLVED,
                    finding=finding,
                )

    if assign_set:
        if assigned_to_operator_id is None:
            finding.assigned_to_operator_id = None
            changes["assigned_to_operator_id"] = None
        else:
            assignee = db.get(Operator, assigned_to_operator_id)
            if assignee is None or assignee.org_id != org.id:
                raise HTTPException(status_code=422, detail="assigned_to_operator_id must be an operator in this org")
            finding.assigned_to_operator_id = assigned_to_operator_id
            changes["assigned_to_operator_id"] = str(assigned_to_operator_id)

    if changes:
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="finding.updated",
            target_type="finding",
            target_id=finding.id,
            context=changes,
        )
    return changes
