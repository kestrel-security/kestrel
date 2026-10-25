# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Audit log read API.

Read-only by construction: `audit_log` is append-only, so there is no POST,
PATCH, or DELETE here. Rows are written by `kestrel.audit.record_audit_event`
from the routes that perform the mutation, inside that mutation's own
transaction -- an action and its audit record commit or roll back together.

Gated at `admin` rather than `read_only`: the log spans every operator's
actions, so it is a different sensitivity class from the security findings
an analyst reads day to day.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from kestrel.audit.export import (
    CSV_FIELDNAMES,
    EXPORT_AUDIT_MAX,
    audit_log_csv_rows,
    audit_log_json_safe,
    audit_summary,
    export_audit_log_for_org,
)
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.security.csv_safe import csv_safe_row
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.pagination import apply_keyset, build_page, normalize_limit

router = APIRouter(prefix="/audit-log", tags=["audit"])

_EXPORT_FORMATS = frozenset({"csv", "json"})


@router.get("")
def list_audit_log(
    action: str | None = Query(default=None, description="Exact action match, e.g. 'finding.status_changed'."),
    actor_operator_id: uuid.UUID | None = None,
    target_id: uuid.UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    """Most recent first (`created_at DESC, id DESC`). Cursor-paginated;
    returns `{items, next_cursor}` like the other list endpoints."""
    stmt = select(AuditLog).where(AuditLog.org_id == org.id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor_operator_id:
        stmt = stmt.where(AuditLog.actor_operator_id == actor_operator_id)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)

    page_limit = normalize_limit(limit)
    stmt = apply_keyset(stmt, sort_column=AuditLog.created_at, id_column=AuditLog.id, cursor=cursor, limit=page_limit)
    rows = list(db.scalars(stmt).all())
    return build_page(rows, limit=page_limit, sort_attr="created_at", serializer=lambda r: audit_summary(db, r))


@router.get("/export")
def export_audit_log(
    format: str = Query(default="csv", description="csv | json"),
    action: str | None = Query(default=None, description="Exact action match."),
    actor_operator_id: uuid.UUID | None = None,
    target_id: uuid.UUID | None = None,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> Response:
    """Auditor export of audit rows matching list filters (capped at EXPORT_AUDIT_MAX)."""
    fmt = format.strip().lower()
    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(status_code=422, detail="format must be csv or json")

    items = export_audit_log_for_org(
        db,
        org.id,
        action=action,
        actor_operator_id=actor_operator_id,
        target_id=target_id,
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"kestrel-audit-log-{stamp}.{fmt}"

    if fmt == "json":
        payload = json.dumps(
            {
                "exported_at": datetime.now(UTC).isoformat(),
                "truncated": len(items) >= EXPORT_AUDIT_MAX,
                "items": audit_log_json_safe(items),
            },
            indent=2,
        )
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDNAMES)
    writer.writeheader()
    for row in audit_log_csv_rows(items):
        writer.writerow(csv_safe_row(row))
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
