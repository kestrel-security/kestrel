# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Findings collection routes: list, ownership queues, saved filter presets,
export, and bulk status/assignment changes.

List and export share their filters via `kestrel.findings.listing` (aging +
export; subject/app filters for investigation loops). Bulk changes require
the analyst role and reuse the single-finding PATCH semantics.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from kestrel.db.models.finding import Finding
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Severity
from kestrel.findings.investigation.status import FindingInvestigationError
from kestrel.findings.listing import (
    EXPORT_FINDINGS_MAX,
    FindingListError,
    apply_finding_filters,
    export_findings_for_org,
    ownership_queues,
)
from kestrel.findings.presets import (
    FindingPresetError,
    create_or_update_preset,
    delete_preset,
    list_presets,
    touch_preset,
    update_preset,
)
from kestrel.security.csv_safe import csv_safe_row
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_current_org, get_db, require_role
from kestrel_api.pagination import apply_keyset, build_page, normalize_limit
from kestrel_api.routers.findings._shared import _EXPORT_FORMATS, _apply_finding_patch, _summary
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingPresetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    filters: dict[str, Any] = Field(default_factory=dict)


class FindingPresetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    filters: dict[str, Any] | None = None
    is_favorite: bool | None = None


def _apply_list_filters(
    stmt,
    db: Session,
    org: Organization,
    *,
    status: str | None,
    severity: str | None,
    search: str | None,
    policy_version_id: uuid.UUID | None,
    policy_slug: str | None,
    assigned_to_operator_id: uuid.UUID | None,
    unassigned: bool | None,
    open_older_than_days: int | None,
    subject_id: uuid.UUID | None = None,
    subject_type: str | None = None,
    application_instance_id: uuid.UUID | None = None,
):
    try:
        return apply_finding_filters(
            stmt,
            db,
            org.id,
            status=status,
            severity=severity,
            search=search,
            policy_version_id=policy_version_id,
            policy_slug=policy_slug,
            assigned_to_operator_id=assigned_to_operator_id,
            unassigned=unassigned,
            open_older_than_days=open_older_than_days,
            subject_id=subject_id,
            subject_type=subject_type,
            application_instance_id=application_instance_id,
        )
    except FindingInvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FindingListError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/queues")
def finding_ownership_queues(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """SecOps ownership queues for open findings."""
    return ownership_queues(db, org.id, viewer_operator_id=operator.id)


@router.get("/presets")
def get_finding_presets(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Per-operator saved findings filter presets."""
    return list_presets(db, org_id=org.id, operator_id=operator.id)


@router.post("/presets", status_code=201)
def create_finding_preset(
    body: FindingPresetCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Create or upsert a named filter preset for the calling operator."""
    try:
        row = create_or_update_preset(
            db,
            org_id=org.id,
            operator_id=operator.id,
            name=body.name,
            filters=body.filters,
        )
    except FindingPresetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return {
        "id": row.id,
        "name": row.name,
        "filters": dict(row.filters or {}),
        "is_favorite": row.is_favorite,
        "last_used_at": row.last_used_at.isoformat(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.patch("/presets/{preset_id}")
def patch_finding_preset(
    preset_id: uuid.UUID,
    body: FindingPresetPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Rename, update filters, and/or favorite a preset owned by the caller."""
    if body.name is None and body.filters is None and body.is_favorite is None:
        raise HTTPException(status_code=422, detail="no fields to update")
    try:
        row = update_preset(
            db,
            org_id=org.id,
            operator_id=operator.id,
            preset_id=preset_id,
            name=body.name,
            filters=body.filters,
            is_favorite=body.is_favorite,
        )
    except FindingPresetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Preset not found")
    db.commit()
    return {
        "id": row.id,
        "name": row.name,
        "filters": dict(row.filters or {}),
        "is_favorite": row.is_favorite,
        "last_used_at": row.last_used_at.isoformat(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.post("/presets/{preset_id}/use")
def use_finding_preset(
    preset_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Bump last_used_at when the operator applies a preset in the UI."""
    row = touch_preset(db, org_id=org.id, operator_id=operator.id, preset_id=preset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Preset not found")
    db.commit()
    return {
        "id": row.id,
        "name": row.name,
        "filters": dict(row.filters or {}),
        "is_favorite": row.is_favorite,
        "last_used_at": row.last_used_at.isoformat(),
    }


@router.delete("/presets/{preset_id}", status_code=204)
def remove_finding_preset(
    preset_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    operator: Operator = Depends(get_current_operator),
) -> None:
    if not delete_preset(db, org_id=org.id, operator_id=operator.id, preset_id=preset_id):
        raise HTTPException(status_code=404, detail="Preset not found")
    db.commit()


@router.get("")
def list_findings(
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    assigned_to_operator_id: uuid.UUID | None = None,
    unassigned: bool | None = Query(
        default=None,
        description="When true, only findings with no assignee (ownership queue).",
    ),
    open_older_than_days: int | None = Query(
        default=None,
        description="Open findings first seen at least this many days ago (SLA aging).",
    ),
    subject_id: uuid.UUID | None = None,
    subject_type: str | None = None,
    application_instance_id: uuid.UUID | None = None,
    sort: str = Query(
        default="severity",
        description=(
            "`severity` (default): worst first, newest first-detected within a severity. "
            "`newest`: purely by first detection, newest first. `last_seen` is accepted as an alias of `newest`."
        ),
    ),
    limit: int | None = None,
    cursor: str | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Sorted by `severity DESC, first_seen_at DESC, id DESC` by default --
    worst first, most recently detected within a severity. Pass
    `sort=newest` for the purely chronological order.

    Severity leads because every finding from one policy evaluation shares a
    timestamp, so ordering by time alone groups the list by policy and the
    first screen is often ten copies of one title -- which buries a lone
    critical under a wall of mediums.

    Pages on `first_seen_at`, never `last_seen_at`: every evaluation bumps
    `last_seen_at` (every few minutes), and a keyset cursor on a column that
    moves under it skips every row that was touched between two pages.

    Returns `{items, next_cursor}`; `next_cursor` is null on the last page.

    `search` matches finding `title` (case-insensitive substring).
    `policy_slug` matches any version of an org policy with that slug
    (preferred for UI chips; `policy_version_id` remains for exact version).
    `unassigned=true` is the unowned queue (mutually exclusive with assignee).
    `open_older_than_days` forces status=open and filters by `first_seen_at`.
    `subject_id` / `subject_type` scope to one investigation subject.
    `application_instance_id` scopes via subject ownership of that SaaS app.
    """
    stmt = select(Finding).where(Finding.org_id == org.id)
    stmt = _apply_list_filters(
        stmt,
        db,
        org,
        status=status,
        severity=severity,
        search=search,
        policy_version_id=policy_version_id,
        policy_slug=policy_slug,
        assigned_to_operator_id=assigned_to_operator_id,
        unassigned=unassigned,
        open_older_than_days=open_older_than_days,
        subject_id=subject_id,
        subject_type=subject_type,
        application_instance_id=application_instance_id,
    )

    if sort not in ("severity", "newest", "last_seen"):
        raise HTTPException(status_code=422, detail="sort must be 'severity' or 'newest'")

    page_limit = normalize_limit(limit)
    ranked = sort == "severity"
    stmt = apply_keyset(
        stmt,
        sort_column=Finding.first_seen_at,
        id_column=Finding.id,
        cursor=cursor,
        limit=page_limit,
        # Postgres orders a native enum by declaration order (low -> critical),
        # so DESC is worst-first without a CASE expression.
        rank_column=Finding.severity if ranked else None,
        rank_decoder=Severity if ranked else None,
    )
    rows = list(db.scalars(stmt).all())
    return build_page(
        rows,
        limit=page_limit,
        sort_attr="first_seen_at",
        serializer=lambda f: _summary(db, f),
        rank_attr="severity" if ranked else None,
    )


@router.get("/export")
def export_findings(
    format: str = Query(default="csv", description="csv | json"),
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    policy_version_id: uuid.UUID | None = None,
    policy_slug: str | None = None,
    assigned_to_operator_id: uuid.UUID | None = None,
    unassigned: bool | None = None,
    open_older_than_days: int | None = None,
    subject_id: uuid.UUID | None = None,
    subject_type: str | None = None,
    application_instance_id: uuid.UUID | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> Response:
    """Auditor/SecOps export of findings matching list filters (capped)."""
    fmt = format.strip().lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(status_code=422, detail="format must be csv or json")

    try:
        rows = export_findings_for_org(
            db,
            org.id,
            status=status,
            severity=severity,
            search=search,
            policy_version_id=policy_version_id,
            policy_slug=policy_slug,
            assigned_to_operator_id=assigned_to_operator_id,
            unassigned=unassigned,
            open_older_than_days=open_older_than_days,
            subject_id=subject_id,
            subject_type=subject_type,
            application_instance_id=application_instance_id,
        )
    except FindingInvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FindingListError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    stamp = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"kestrel-findings-{stamp}.{fmt}"

    if fmt == "json":
        payload = json.dumps(
            {
                "exported_at": datetime.now(UTC).isoformat(),
                "truncated": len(rows) >= EXPORT_FINDINGS_MAX,
                "findings": _json_safe(rows),
            },
            indent=2,
        )
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "id",
            "title",
            "severity",
            "status",
            "policy_slug",
            "subject_type",
            "subject_id",
            "age_days",
            "first_seen_at",
            "last_seen_at",
            "resolved_at",
            "assigned_to_email",
        ],
    )
    writer.writeheader()
    for row in rows:
        assigned = row.get("assigned_to") or {}
        writer.writerow(
            csv_safe_row(
                {
                    "id": str(row["id"]),
                    "title": row["title"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "policy_slug": row.get("policy_slug") or "",
                    "subject_type": row["subject_type"],
                    "subject_id": str(row["subject_id"]),
                    "age_days": row.get("age_days", ""),
                    "first_seen_at": row["first_seen_at"],
                    "last_seen_at": row["last_seen_at"],
                    "resolved_at": row.get("resolved_at") or "",
                    "assigned_to_email": assigned.get("email") or "",
                }
            )
        )
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json_safe(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        item = {
            **row,
            "id": str(row["id"]),
            "subject_id": str(row["subject_id"]),
            "policy_version_id": str(row["policy_version_id"]),
        }
        assigned = row.get("assigned_to")
        if assigned is not None:
            item["assigned_to"] = {**assigned, "id": str(assigned["id"])}
        out.append(item)
    return out


BULK_FINDINGS_MAX = 100


class FindingBulkPatch(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=BULK_FINDINGS_MAX)
    status: str | None = None
    # Use model_fields_set so null explicitly unassigns rather than meaning "no change".
    assigned_to_operator_id: uuid.UUID | None = None


@router.post("/bulk")
def bulk_patch_findings(
    body: FindingBulkPatch,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    """Apply the same status and/or assignment change to many findings.

    Unknown or cross-org ids are reported in `not_found` and skipped; each
    updated finding gets its own `finding.updated` audit row and webhooks
    (same semantics as PATCH /findings/{id}).
    """
    if body.status is None and "assigned_to_operator_id" not in body.model_fields_set:
        raise HTTPException(
            status_code=422,
            detail="Provide status and/or assigned_to_operator_id",
        )

    # Preserve request order while de-duplicating.
    seen: set[uuid.UUID] = set()
    ordered_ids: list[uuid.UUID] = []
    for fid in body.finding_ids:
        if fid not in seen:
            seen.add(fid)
            ordered_ids.append(fid)

    findings_by_id = {
        f.id: f for f in db.scalars(select(Finding).where(Finding.org_id == org.id, Finding.id.in_(ordered_ids))).all()
    }

    webhook_delivery_ids: list = []
    updated: list[dict] = []
    not_found: list[str] = []
    for fid in ordered_ids:
        finding = findings_by_id.get(fid)
        if finding is None:
            not_found.append(str(fid))
            continue
        _apply_finding_patch(
            db,
            finding=finding,
            org=org,
            actor=actor,
            status=body.status,
            assign_set="assigned_to_operator_id" in body.model_fields_set,
            assigned_to_operator_id=body.assigned_to_operator_id,
            webhook_delivery_ids=webhook_delivery_ids,
        )
        updated.append(_summary(db, finding))

    db.commit()
    if webhook_delivery_ids:
        tasks.enqueue_webhook_deliveries([str(d) for d in webhook_delivery_ids])
    return {
        "updated": updated,
        "updated_count": len(updated),
        "not_found": not_found,
    }
