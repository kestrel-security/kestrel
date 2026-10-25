# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resources: the repositories, channels, drives, and sites connectors collect.

Read endpoints for the identity-detail and finding-subject surfaces, plus the
one write the product has over inventory: an operator's sensitivity decision.
Connectors guess sensitivity from a name or a topic; the person reviewing the
finding knows. The override is stored on the resource's ``config`` and
survives every later sync (see ``sync.upsert._preserve_sensitivity_override``).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.audit.service import record_audit_event
from kestrel.db.base import is_active
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.resource import Resource, ResourceType
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.pagination import apply_keyset, build_page, normalize_limit

router = APIRouter(prefix="/resources", tags=["resources"])


def _serialize(resource: Resource) -> dict:
    config = resource.config or {}
    return {
        "id": resource.id,
        "resource_type": resource.resource_type.value,
        "name": resource.name,
        "visibility": resource.visibility.value if resource.visibility else None,
        "is_sensitive": resource.is_sensitive,
        "sensitivity_source": config.get("sensitivity_source"),
        "sensitivity_reasons": config.get("sensitivity_reasons") or [],
        "application_instance_id": resource.application_instance_id,
        "provider_object_id": resource.provider_object_id,
        "config": config,
        "created_at": resource.created_at.isoformat() if resource.created_at else None,
    }


@router.get("")
def list_resources(
    resource_type: str | None = Query(default=None),
    is_sensitive: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    application_instance_id: uuid.UUID | None = Query(default=None),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    page_limit = normalize_limit(limit)
    stmt = select(Resource).where(Resource.org_id == org.id, is_active(Resource))

    if resource_type is not None:
        try:
            parsed = ResourceType(resource_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unknown resource_type '{resource_type}'") from exc
        stmt = stmt.where(Resource.resource_type == parsed)
    if is_sensitive is not None:
        stmt = stmt.where(Resource.is_sensitive.is_(is_sensitive))
    if search and search.strip():
        stmt = stmt.where(Resource.name.ilike(f"%{search.strip()}%"))
    if application_instance_id is not None:
        stmt = stmt.where(Resource.application_instance_id == application_instance_id)

    stmt = apply_keyset(stmt, sort_column=Resource.created_at, id_column=Resource.id, cursor=cursor, limit=page_limit)
    rows = list(db.scalars(stmt).all())
    return build_page(rows, limit=page_limit, sort_attr="created_at", serializer=_serialize)


@router.get("/{resource_id}")
def get_resource(
    resource_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    resource = db.get(Resource, resource_id)
    if resource is None or resource.org_id != org.id or resource.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Resource not found")
    return _serialize(resource)


class SensitivityUpdate(BaseModel):
    """``None`` clears the override and returns the resource to the connector's
    own assessment on the next sync."""

    is_sensitive: bool | None


@router.patch("/{resource_id}/sensitivity")
def set_resource_sensitivity(
    resource_id: uuid.UUID,
    body: SensitivityUpdate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    resource = db.get(Resource, resource_id)
    if resource is None or resource.org_id != org.id or resource.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Resource not found")

    config = dict(resource.config or {})
    if body.is_sensitive is None:
        config.pop("sensitivity_override", None)
        config.pop("sensitivity_override_by", None)
        config.pop("sensitivity_override_at", None)
        config["sensitivity_source"] = "heuristic"
    else:
        from datetime import UTC, datetime

        config["sensitivity_override"] = bool(body.is_sensitive)
        config["sensitivity_override_by"] = str(actor.id)
        config["sensitivity_override_at"] = datetime.now(UTC).isoformat()
        config["sensitivity_source"] = "operator"
        resource.is_sensitive = bool(body.is_sensitive)
    resource.config = config

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="resource.sensitivity_set",
        target_type="resource",
        target_id=resource.id,
        context={"is_sensitive": body.is_sensitive, "resource_name": resource.name},
    )
    db.commit()
    db.refresh(resource)
    return _serialize(resource)
