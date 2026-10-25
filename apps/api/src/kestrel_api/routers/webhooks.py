# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Webhook endpoint CRUD + delivery history / retry.

Admin-only: endpoints hold outbound URLs and signing secrets. Creates return
the plaintext signing secret once; it is never readable again (rotate
instead). Delivery is async via Celery after finding open/resolve events.
Failed or stuck pending deliveries can be re-enqueued by admins.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.webhook import WebhookDelivery, WebhookEndpoint
from kestrel.webhooks.authoring import (
    WebhookAuthoringError,
    create_endpoint,
    get_org_endpoint,
    rotate_secret,
    update_endpoint,
)
from kestrel.webhooks.history import (
    WebhookHistoryError,
    delivery_counts,
    delivery_to_dict,
    list_deliveries,
    retry_delivery,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _endpoint_out(endpoint: WebhookEndpoint, *, counts: dict[str, int] | None = None) -> dict:
    body = {
        "id": endpoint.id,
        "name": endpoint.name,
        "url": endpoint.url,
        "description": endpoint.description,
        "events": list(endpoint.events or []),
        "is_enabled": endpoint.is_enabled,
        "created_at": endpoint.created_at.isoformat() if endpoint.created_at else None,
        "updated_at": endpoint.updated_at.isoformat() if endpoint.updated_at else None,
    }
    if counts is not None:
        body["delivery_counts"] = counts
    return body


@router.get("")
def list_webhooks(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> list[dict]:
    rows = db.scalars(
        select(WebhookEndpoint).where(WebhookEndpoint.org_id == org.id).order_by(WebhookEndpoint.created_at.desc())
    ).all()
    return [_endpoint_out(r, counts=delivery_counts(db, org_id=org.id, endpoint_id=r.id)) for r in rows]


class WebhookCreate(BaseModel):
    name: str
    url: str
    events: list[str] = Field(min_length=1)
    description: str | None = None


@router.post("", status_code=201)
def create_webhook(
    body: WebhookCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    try:
        endpoint, secret = create_endpoint(
            db,
            org_id=org.id,
            name=body.name,
            url=body.url,
            events=body.events,
            description=body.description,
        )
    except WebhookAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="webhook.created",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
        context={"name": endpoint.name, "url": endpoint.url, "events": endpoint.events},
    )
    db.commit()
    return {
        **_endpoint_out(endpoint, counts=delivery_counts(db, org_id=org.id, endpoint_id=endpoint.id)),
        "signing_secret": secret,
    }


@router.get("/{webhook_id}")
def get_webhook(
    webhook_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _endpoint_out(endpoint, counts=delivery_counts(db, org_id=org.id, endpoint_id=endpoint.id))


class WebhookPatch(BaseModel):
    name: str | None = None
    url: str | None = None
    events: list[str] | None = None
    description: str | None = None
    is_enabled: bool | None = None


@router.patch("/{webhook_id}")
def patch_webhook(
    webhook_id: uuid.UUID,
    patch: WebhookPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        update_endpoint(
            db,
            endpoint,
            name=patch.name,
            url=patch.url,
            events=patch.events,
            description=patch.description,
            is_enabled=patch.is_enabled,
            description_set="description" in patch.model_fields_set,
        )
    except WebhookAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="webhook.updated",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
        context={k: getattr(patch, k) for k in patch.model_fields_set},
    )
    db.commit()
    return _endpoint_out(endpoint, counts=delivery_counts(db, org_id=org.id, endpoint_id=endpoint.id))


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> None:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Deliveries reference the endpoint; drop history with the endpoint so
    # we don't leave FK orphans. History is operational, not compliance audit.
    db.query(WebhookDelivery).filter(WebhookDelivery.webhook_endpoint_id == endpoint.id).delete()
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="webhook.deleted",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
        context={"name": endpoint.name, "url": endpoint.url},
    )
    db.delete(endpoint)
    db.commit()


@router.post("/{webhook_id}/rotate-secret", status_code=200)
def rotate_webhook_secret(
    webhook_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    secret = rotate_secret(db, endpoint)
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="webhook.secret_rotated",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
    )
    db.commit()
    return {"id": endpoint.id, "signing_secret": secret}


@router.get("/{webhook_id}/deliveries")
def get_deliveries(
    webhook_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    status: str | None = Query(None, description="pending | success | failed"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> list[dict]:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        rows = list_deliveries(db, org_id=org.id, endpoint_id=endpoint.id, status=status, limit=limit)
    except WebhookHistoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [delivery_to_dict(r) for r in rows]


@router.post("/{webhook_id}/deliveries/{delivery_id}/retry", status_code=200)
def retry_webhook_delivery(
    webhook_id: uuid.UUID,
    delivery_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    endpoint = get_org_endpoint(db, org.id, webhook_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        delivery = retry_delivery(db, org_id=org.id, endpoint=endpoint, delivery_id=delivery_id)
    except WebhookHistoryError as exc:
        detail = str(exc)
        code = 404 if detail == "delivery not found" else 400
        raise HTTPException(status_code=code, detail=detail) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="webhook.delivery_retried",
        target_type="webhook_delivery",
        target_id=delivery.id,
        context={
            "webhook_endpoint_id": str(endpoint.id),
            "event_type": delivery.event_type,
            "finding_id": str(delivery.finding_id) if delivery.finding_id else None,
            "attempt_count": delivery.attempt_count,
        },
    )
    db.commit()
    tasks.enqueue_webhook_deliveries([str(delivery.id)])
    return delivery_to_dict(delivery)
