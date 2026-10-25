# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator posture dashboard API + widget layout."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from kestrel.dashboard.first_run import dismiss_first_run, first_run_dismissed, restore_first_run
from kestrel.dashboard.layout import get_layout_response, reset_layout, save_layout
from kestrel.dashboard.overview import posture_overview
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class DashboardLayoutWidgetIn(BaseModel):
    id: str


class DashboardLayoutIn(BaseModel):
    version: int = 1
    widgets: list[DashboardLayoutWidgetIn] = Field(default_factory=list)


@router.get("")
def get_dashboard(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Org-scoped posture overview for the operator home dashboard."""
    return posture_overview(
        db,
        org.id,
        viewer_operator_id=operator.id,
        first_run_dismissed=first_run_dismissed(operator),
    )


@router.get("/layout")
def get_dashboard_layout(
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    """Per-operator widget layout (defaults when unset)."""
    return get_layout_response(operator)


@router.put("/layout")
def put_dashboard_layout(
    body: DashboardLayoutIn,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    """Save the calling operator's dashboard widget layout."""
    try:
        result = save_layout(db, operator, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(operator)
    return result


@router.post("/layout/reset")
def reset_dashboard_layout(
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    """Clear saved layout so the default overview is restored."""
    result = reset_layout(db, operator)
    db.commit()
    db.refresh(operator)
    return result


@router.post("/first-run/dismiss")
def dismiss_first_run_checklist(
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    """Hide the getting-started checklist for the calling operator until restored."""
    result = dismiss_first_run(db, operator)
    db.commit()
    return result


@router.post("/first-run/restore")
def restore_first_run_checklist(
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict[str, Any]:
    """Show the getting-started checklist again for the calling operator."""
    result = restore_first_run(db, operator)
    db.commit()
    return result
