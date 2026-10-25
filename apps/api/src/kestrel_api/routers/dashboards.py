# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Multi-dashboard API."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import Response as FastAPIResponse
from kestrel.audit.service import record_audit_event
from kestrel.dashboard import boards as boards_svc
from kestrel.dashboard.export import export_dashboard
from kestrel.dashboard.extras import execute_query_cached
from kestrel.dashboard.query_dsl import parse_query_spec
from kestrel.dashboard.schedules import (
    create_schedule,
    delete_schedule,
    list_schedules_for_dashboard,
    update_schedule,
)
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db, require_role

router = APIRouter(prefix="/dashboards", tags=["dashboards"])


class DashboardCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = None
    description: str | None = None
    visibility: str = "org"
    template: str | None = None


class DashboardUpdateIn(BaseModel):
    name: str | None = None
    description: str | None = None
    visibility: str | None = None


class WidgetCreateIn(BaseModel):
    widget_key: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    viz_type: str
    query_spec: dict[str, Any] = Field(default_factory=dict)
    layout: dict[str, Any] | None = None
    sort_order: int = 0
    body_markdown: str | None = None
    refresh_seconds: int | None = None
    preset_id: str | None = None


class WidgetUpdateIn(BaseModel):
    title: str | None = None
    viz_type: str | None = None
    query_spec: dict[str, Any] | None = None
    layout: dict[str, Any] | None = None
    sort_order: int | None = None
    body_markdown: str | None = None
    refresh_seconds: int | None = None


class LayoutBatchIn(BaseModel):
    layouts: list[dict[str, Any]]


class QueryPreviewIn(BaseModel):
    query_spec: dict[str, Any]


class PinHomeIn(BaseModel):
    dashboard_id: uuid.UUID | None = None


class ScheduleCreateIn(BaseModel):
    cron: str
    timezone: str = "UTC"
    format: str = "pdf"
    recipient_operator_ids: list[str]


class ScheduleUpdateIn(BaseModel):
    cron: str | None = None
    timezone: str | None = None
    format: str | None = None
    enabled: bool | None = None
    recipient_operator_ids: list[str] | None = None


#: Errors the dashboard service raises for caller mistakes; anything else is a bug and propagates as a 500.
_SERVICE_ERRORS = (LookupError, PermissionError, ValueError)


def _map_err(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.get("")
def list_dashboards(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    items = boards_svc.list_dashboards(db, org_id=org.id, operator=operator)
    db.commit()
    return {"dashboards": items}


@router.get("/presets")
def get_presets(
    _: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    return boards_svc.presets_payload()


@router.post("/query/preview")
def query_preview(
    body: QueryPreviewIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        spec = parse_query_spec(body.query_spec)
        return execute_query_cached(db, org_id=org.id, spec=spec, viewer_operator_id=operator.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pin-home")
def pin_home(
    body: PinHomeIn,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    result = boards_svc.pin_home(db, operator=operator, dashboard_id=body.dashboard_id)
    db.commit()
    return result


@router.post("")
def create_dashboard(
    body: DashboardCreateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        created = boards_svc.create_dashboard(
            db,
            org_id=org.id,
            operator=operator,
            name=body.name,
            slug=body.slug,
            description=body.description,
            visibility=body.visibility,
            template=body.template,
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.create",
        target_type="dashboard",
        target_id=uuid.UUID(created["id"]),
        context={"name": created["name"], "slug": created["slug"]},
    )
    db.commit()
    return created


@router.get("/{dashboard_id}")
def get_dashboard(
    dashboard_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    try:
        return boards_svc.get_dashboard(db, org_id=org.id, dashboard_id=dashboard_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc


@router.patch("/{dashboard_id}")
def patch_dashboard(
    dashboard_id: uuid.UUID,
    body: DashboardUpdateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        updated = boards_svc.update_dashboard(
            db,
            org_id=org.id,
            dashboard_id=dashboard_id,
            operator=operator,
            name=body.name,
            description=body.description,
            visibility=body.visibility,
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.update",
        target_type="dashboard",
        target_id=dashboard_id,
    )
    db.commit()
    return updated


@router.delete("/{dashboard_id}", status_code=204)
def remove_dashboard(
    dashboard_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> Response:
    try:
        boards_svc.delete_dashboard(db, org_id=org.id, dashboard_id=dashboard_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.delete",
        target_type="dashboard",
        target_id=dashboard_id,
    )
    db.commit()
    return Response(status_code=204)


@router.post("/{dashboard_id}/duplicate")
def duplicate(
    dashboard_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        created = boards_svc.duplicate_dashboard(db, org_id=org.id, dashboard_id=dashboard_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.duplicate",
        target_type="dashboard",
        target_id=uuid.UUID(created["id"]),
        context={"from": str(dashboard_id)},
    )
    db.commit()
    return created


@router.post("/{dashboard_id}/set-default")
def set_default(
    dashboard_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, Any]:
    try:
        result = boards_svc.set_default_dashboard(db, org_id=org.id, dashboard_id=dashboard_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    db.commit()
    return result


@router.put("/{dashboard_id}/layout")
def put_layout(
    dashboard_id: uuid.UUID,
    body: LayoutBatchIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        result = boards_svc.save_layouts(
            db,
            org_id=org.id,
            dashboard_id=dashboard_id,
            operator=operator,
            layouts=body.layouts,
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    db.commit()
    return result


@router.post("/{dashboard_id}/widgets")
def create_widget(
    dashboard_id: uuid.UUID,
    body: WidgetCreateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        if body.preset_id:
            w = boards_svc.add_preset_widget(
                db,
                org_id=org.id,
                dashboard_id=dashboard_id,
                operator=operator,
                preset_id=body.preset_id,
            )
        else:
            w = boards_svc.add_widget(
                db,
                org_id=org.id,
                dashboard_id=dashboard_id,
                operator=operator,
                widget_key=body.widget_key,
                title=body.title,
                viz_type=body.viz_type,
                query_spec=body.query_spec,
                layout=body.layout,
                sort_order=body.sort_order,
                body_markdown=body.body_markdown,
                refresh_seconds=body.refresh_seconds,
            )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.widget.create",
        target_type="dashboard_widget",
        target_id=uuid.UUID(w["id"]),
        context={"dashboard_id": str(dashboard_id)},
    )
    db.commit()
    return w


@router.patch("/{dashboard_id}/widgets/{widget_id}")
def patch_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    body: WidgetUpdateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict[str, Any]:
    try:
        w = boards_svc.update_widget(
            db,
            org_id=org.id,
            dashboard_id=dashboard_id,
            widget_id=widget_id,
            operator=operator,
            **body.model_dump(exclude_unset=True),
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    db.commit()
    return w


@router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=204)
def remove_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> Response:
    try:
        boards_svc.delete_widget(db, org_id=org.id, dashboard_id=dashboard_id, widget_id=widget_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    db.commit()
    return Response(status_code=204)


@router.post("/{dashboard_id}/export")
def export(
    dashboard_id: uuid.UUID,
    format: str = "pdf",
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> FastAPIResponse:
    try:
        payload, media, filename = export_dashboard(
            db, org_id=org.id, dashboard_id=dashboard_id, operator=operator, fmt=format
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.export",
        target_type="dashboard",
        target_id=dashboard_id,
        context={"format": format, "bytes": len(payload)},
    )
    db.commit()
    return FastAPIResponse(
        content=payload,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{dashboard_id}/schedules")
def get_schedules(
    dashboard_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, Any]:
    return {"schedules": list_schedules_for_dashboard(db, org_id=org.id, dashboard_id=dashboard_id)}


@router.post("/{dashboard_id}/schedules")
def post_schedule(
    dashboard_id: uuid.UUID,
    body: ScheduleCreateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, Any]:
    try:
        created = create_schedule(
            db,
            org_id=org.id,
            dashboard_id=dashboard_id,
            operator=operator,
            cron=body.cron,
            timezone=body.timezone,
            fmt=body.format,
            recipient_operator_ids=body.recipient_operator_ids,
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.schedule.create",
        target_type="dashboard_schedule",
        target_id=uuid.UUID(created["id"]),
    )
    db.commit()
    return created


@router.patch("/{dashboard_id}/schedules/{schedule_id}")
def patch_schedule(
    dashboard_id: uuid.UUID,
    schedule_id: uuid.UUID,
    body: ScheduleUpdateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, Any]:
    try:
        updated = update_schedule(
            db,
            org_id=org.id,
            dashboard_id=dashboard_id,
            schedule_id=schedule_id,
            operator=operator,
            **body.model_dump(exclude_unset=True),
        )
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.schedule_updated",
        target_type="dashboard",
        target_id=dashboard_id,
        context={"schedule_id": str(schedule_id), "fields": sorted(body.model_dump(exclude_unset=True))},
    )
    db.commit()
    return updated


@router.delete("/{dashboard_id}/schedules/{schedule_id}", status_code=204)
def remove_schedule(
    dashboard_id: uuid.UUID,
    schedule_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> Response:
    try:
        delete_schedule(db, org_id=org.id, dashboard_id=dashboard_id, schedule_id=schedule_id, operator=operator)
    except _SERVICE_ERRORS as exc:
        raise _map_err(exc) from exc
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="dashboard.schedule_deleted",
        target_type="dashboard",
        target_id=dashboard_id,
        context={"schedule_id": str(schedule_id)},
    )
    db.commit()
    return Response(status_code=204)
