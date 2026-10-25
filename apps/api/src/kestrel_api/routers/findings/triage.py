# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Findings triage routes: exceptions, mute/unmute, watchers, and tickets.

Covers the exception and mute expiry review queues, recording an exception,
mute/snooze with a required expiry (distinct from an exception), per-operator
watches and the watched-findings digest, and one-click TicketProvider issue
creation. Mutating routes require at least the analyst role (watching only
requires an authenticated operator); `created_by` on an exception is always
the authenticated caller, never client-supplied.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.audit.service import record_audit_event
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.webhook import FINDING_OPENED
from kestrel.findings.exceptions_queue import DEFAULT_WITHIN_DAYS, expiring_exceptions
from kestrel.findings.investigation.status import FindingInvestigationError, create_finding_exception
from kestrel.findings.mute import DEFAULT_WITHIN_DAYS as MUTE_WITHIN_DAYS
from kestrel.findings.mute import expiring_mutes, mute_finding, mute_finding_for_days, unmute_finding
from kestrel.findings.watch_digest import build_watch_digest, preview_watch_digest
from kestrel.findings.watchers import FindingWatcherError, is_watching, list_watched_findings, unwatch_finding, watch_finding
from kestrel.notifications.dispatch import schedule_finding_notifications
from kestrel.ticketing.authoring import get_org_integration
from kestrel.ticketing.create import TicketCreateError, create_ticket_for_finding, list_finding_tickets, ticket_out
from kestrel.webhooks.dispatch import schedule_finding_webhooks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db, require_role
from kestrel_api.routers.findings._shared import _summary
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/findings", tags=["findings"])


class ExceptionIn(BaseModel):
    reason: str = Field(min_length=1)
    expires_at: datetime | None = None


class MuteIn(BaseModel):
    """Mute with either a duration preset (`days`) or an absolute `muted_until`."""

    days: int | None = Field(default=None, ge=1, le=90)
    muted_until: datetime | None = None
    reason: str | None = Field(default=None, max_length=2000)


class CreateTicketIn(BaseModel):
    integration_id: uuid.UUID
    dry_run: bool = False


@router.get("/exceptions/expiring")
def list_expiring_exceptions(
    within_days: int = Query(
        default=DEFAULT_WITHIN_DAYS,
        ge=0,
        le=365,
        description="Include exceptions expiring within this many days (plus already expired).",
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Exception expiry review queue for findings in exception status."""
    return expiring_exceptions(db, org.id, within_days=within_days)


@router.get("/mutes/expiring")
def list_expiring_mutes(
    within_days: int = Query(
        default=MUTE_WITHIN_DAYS,
        ge=0,
        le=365,
        description="Include mutes expiring within this many days (plus already expired).",
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Mute/snooze expiry review queue — distinct from exceptions."""
    return expiring_mutes(db, org.id, within_days=within_days)


@router.get("/watched")
def list_watched(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Findings the calling operator is watching."""
    items = list_watched_findings(db, org_id=org.id, operator_id=operator.id, limit=limit)
    return {
        "items": [
            {
                **row,
                "id": str(row["id"]),
                "subject_id": str(row["subject_id"]),
                "policy_version_id": str(row["policy_version_id"]),
                "assigned_to": (
                    {
                        **row["assigned_to"],
                        "id": str(row["assigned_to"]["id"]),
                    }
                    if row.get("assigned_to")
                    else None
                ),
            }
            for row in items
        ]
    }


@router.get("/watched/digest")
def get_watched_digest(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Structured watched-findings digest for the calling operator."""
    return build_watch_digest(db, org_id=org.id, operator_id=operator.id, days=days)


@router.post("/watched/digest-preview")
def preview_watched_digest(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Preview the caller's watched-findings digest email. Sends nothing.

    Returns the digest plus whether the next scheduled run would send it
    (`would_send`) and, if not, why (`reason`). The weekly digest itself goes
    out from the worker's beat schedule.
    """
    return preview_watch_digest(db, org_id=org.id, operator=operator, days=days)


@router.post("/{finding_id}/exceptions", status_code=201)
def create_exception(
    finding_id: uuid.UUID,
    body: ExceptionIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        exception = create_finding_exception(
            db,
            finding=finding,
            reason=body.reason,
            created_by_operator_id=actor.id,
            expires_at=body.expires_at,
        )
    except FindingInvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.exception_created",
        target_type="finding",
        target_id=finding.id,
        context={
            "reason": exception.reason,
            "expires_at": exception.expires_at.isoformat() if exception.expires_at else None,
            "exception_id": str(exception.id),
        },
    )
    db.commit()
    return {
        "id": exception.id,
        "finding_id": finding.id,
        "reason": exception.reason,
        "expires_at": exception.expires_at.isoformat() if exception.expires_at else None,
        "created_by": {"id": actor.id, "email": actor.email, "display_name": actor.display_name},
    }


@router.get("/{finding_id}/tickets")
def get_finding_tickets(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """List tickets created from this finding."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"items": list_finding_tickets(db, finding)}


@router.post("/{finding_id}/tickets", status_code=201)
def create_finding_ticket(
    finding_id: uuid.UUID,
    body: CreateTicketIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Create a tracker issue via TicketProvider and record the URL.

    Uses the finding handoff markdown as the issue body. On success, stores a
    ``finding_tickets`` row, appends an investigation note with the URL, and
    audits ``finding.ticket_created``. Pass ``dry_run=true`` to exercise the
    provider without writing rows or calling live HTTP when providers honor dry-run.
    """
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    integration = get_org_integration(db, org.id, body.integration_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="Ticket integration not found")

    try:
        row, result, note = create_ticket_for_finding(
            db,
            finding=finding,
            integration=integration,
            actor_operator_id=actor.id,
            dry_run=body.dry_run,
        )
    except TicketCreateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if body.dry_run:
        return {
            "dry_run": True,
            "provider": integration.provider,
            "external_id": result.external_id,
            "url": result.url,
            "ticket": None,
            "note": None,
        }

    assert row is not None
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.ticket_created",
        target_type="finding",
        target_id=finding.id,
        context={
            "ticket_id": str(row.id),
            "integration_id": str(integration.id),
            "provider": integration.provider,
            "external_id": result.external_id,
            "url": result.url,
            "note_id": str(note["id"]) if note else None,
        },
    )
    if note is not None:
        preview = note["body"] if len(note["body"]) <= 120 else note["body"][:117] + "…"
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="finding.note_added",
            target_type="finding",
            target_id=finding.id,
            context={
                "note_id": str(note["id"]),
                "body_preview": preview,
                "via": "ticket_create",
            },
        )
    db.commit()
    return {
        "dry_run": False,
        "provider": integration.provider,
        "external_id": result.external_id,
        "url": result.url,
        "ticket": ticket_out(row),
        "note": note,
    }


@router.post("/{finding_id}/mute")
def mute_finding_route(
    finding_id: uuid.UUID,
    body: MuteIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Temporarily mute/snooze a finding with a required expiry."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    if body.days is None and body.muted_until is None:
        raise HTTPException(status_code=422, detail="provide days or muted_until")
    if body.days is not None and body.muted_until is not None:
        raise HTTPException(status_code=422, detail="provide only one of days or muted_until")

    try:
        if body.days is not None:
            mute_finding_for_days(finding, days=body.days, reason=body.reason)
        else:
            assert body.muted_until is not None
            mute_finding(finding, muted_until=body.muted_until, reason=body.reason)
    except FindingInvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.muted",
        target_type="finding",
        target_id=finding.id,
        context={
            "muted_until": finding.muted_until.isoformat() if finding.muted_until else None,
            "reason": finding.mute_reason,
        },
    )
    db.commit()
    return _summary(db, finding)


@router.post("/{finding_id}/unmute")
def unmute_finding_route(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    """Clear mute and reopen the finding."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        unmute_finding(finding)
    except FindingInvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    webhook_delivery_ids: list = []
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
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="finding.unmuted",
        target_type="finding",
        target_id=finding.id,
        context={"status": FindingStatus.OPEN.value},
    )
    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])
    return _summary(db, finding)


@router.get("/{finding_id}/watch")
def get_watch_state(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Whether the calling operator is watching this finding."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "finding_id": str(finding.id),
        "watching": is_watching(db, org_id=org.id, operator_id=operator.id, finding_id=finding.id),
    }


@router.post("/{finding_id}/watch")
def watch_finding_route(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Subscribe to in-app updates for this finding. Idempotent."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        watch_finding(db, org_id=org.id, operator_id=operator.id, finding=finding)
    except FindingWatcherError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="finding.watched",
        target_type="finding",
        target_id=finding.id,
        context={},
    )
    db.commit()
    return {"finding_id": str(finding.id), "watching": True}


@router.delete("/{finding_id}/watch")
def unwatch_finding_route(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Unsubscribe from this finding. Idempotent."""
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        unwatch_finding(db, org_id=org.id, operator_id=operator.id, finding=finding)
    except FindingWatcherError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="finding.unwatched",
        target_type="finding",
        target_id=finding.id,
        context={},
    )
    db.commit()
    return {"finding_id": str(finding.id), "watching": False}
