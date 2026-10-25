# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Ticket integration CRUD + token rotate.

Admin-only for create/update/delete/rotate. Analysts may list providers and
integrations (config only — API tokens never returned) so finding Create ticket
can offer a picker.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.ticket import TicketIntegration
from kestrel.ticketing.authoring import (
    TicketAuthoringError,
    create_integration,
    get_org_integration,
    integration_out,
    rotate_token,
    update_integration,
)
from kestrel.ticketing.registry import provider_summaries
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role

router = APIRouter(prefix="/ticket-integrations", tags=["ticket-integrations"])


@router.get("/providers")
def list_ticket_providers(
    _: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    """Built-in + entry-point TicketProvider ids."""
    return {"items": provider_summaries()}


@router.get("")
def list_ticket_integrations(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> list[dict]:
    rows = db.scalars(
        select(TicketIntegration).where(TicketIntegration.org_id == org.id).order_by(TicketIntegration.created_at.desc())
    ).all()
    return [integration_out(r) for r in rows]


class TicketIntegrationCreate(BaseModel):
    name: str
    provider: str
    api_token: str
    config: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None


@router.post("", status_code=201)
def create_ticket_integration(
    body: TicketIntegrationCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    try:
        row = create_integration(
            db,
            org_id=org.id,
            name=body.name,
            provider=body.provider,
            api_token=body.api_token,
            config=body.config,
            description=body.description,
        )
    except TicketAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="ticket_integration.created",
        target_type="ticket_integration",
        target_id=row.id,
        context={"name": row.name, "provider": row.provider},
    )
    db.commit()
    db.refresh(row)
    return integration_out(row)


@router.get("/{integration_id}")
def get_ticket_integration(
    integration_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    row = get_org_integration(db, org.id, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ticket integration not found")
    return integration_out(row)


class TicketIntegrationPatch(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    description: str | None = None
    is_enabled: bool | None = None
    # True when the client intentionally clears description.
    description_set: bool = False
    # Required whenever config.base_url (or another URL field) changes.
    api_token: str | None = None


@router.patch("/{integration_id}")
def patch_ticket_integration(
    integration_id: uuid.UUID,
    body: TicketIntegrationPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    row = get_org_integration(db, org.id, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ticket integration not found")
    try:
        update_integration(
            db,
            row,
            name=body.name,
            config=body.config,
            description=body.description,
            is_enabled=body.is_enabled,
            description_set=body.description_set or body.description is not None,
            api_token=body.api_token,
        )
    except TicketAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="ticket_integration.updated",
        target_type="ticket_integration",
        target_id=row.id,
        context={
            "name": row.name,
            "is_enabled": row.is_enabled,
            "fields": [
                k for k, v in body.model_dump(exclude_unset=True).items() if k not in {"description_set", "api_token"}
            ],
            "token_rotated": bool(body.api_token and body.api_token.strip()),
        },
    )
    db.commit()
    db.refresh(row)
    return integration_out(row)


class RotateTokenIn(BaseModel):
    api_token: str


@router.post("/{integration_id}/rotate-token")
def rotate_ticket_integration_token(
    integration_id: uuid.UUID,
    body: RotateTokenIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    row = get_org_integration(db, org.id, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ticket integration not found")
    try:
        rotate_token(db, row, api_token=body.api_token)
    except TicketAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="ticket_integration.token_rotated",
        target_type="ticket_integration",
        target_id=row.id,
        context={"name": row.name, "provider": row.provider},
    )
    db.commit()
    return {"ok": True, "id": str(row.id)}


@router.delete("/{integration_id}", status_code=204)
def delete_ticket_integration(
    integration_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> None:
    row = get_org_integration(db, org.id, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ticket integration not found")
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="ticket_integration.deleted",
        target_type="ticket_integration",
        target_id=row.id,
        context={"name": row.name, "provider": row.provider},
    )
    db.delete(row)
    db.commit()
