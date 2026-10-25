# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Audit log CSV/JSON export.

Same filters as the paginated list (`action`, `actor_operator_id`, `target_id`),
capped for auditor download. Most recent first.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import Operator

EXPORT_AUDIT_MAX = 10_000

CSV_FIELDNAMES = [
    "id",
    "created_at",
    "action",
    "actor_id",
    "actor_email",
    "actor_display_name",
    "target_type",
    "target_id",
    "context",
]


def audit_summary(db: Session, row: AuditLog) -> dict[str, Any]:
    """Same shape as `GET /audit-log` list items."""
    actor = db.get(Operator, row.actor_operator_id) if row.actor_operator_id else None
    return {
        "id": row.id,
        # Null for actions with no resolvable actor (e.g. a failed login for
        # an unknown email) -- deliberately not collapsed to a placeholder
        # string, which would be indistinguishable from a real operator.
        "actor": ({"id": actor.id, "email": actor.email, "display_name": actor.display_name} if actor else None),
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "context": row.context,
        "created_at": row.created_at.isoformat(),
    }


def export_audit_log_for_org(
    db: Session,
    org_id: uuid.UUID,
    *,
    action: str | None = None,
    actor_operator_id: uuid.UUID | None = None,
    target_id: uuid.UUID | None = None,
    limit: int = EXPORT_AUDIT_MAX,
) -> list[dict[str, Any]]:
    """Flat export rows matching list filters, most recent first, capped."""
    cap = min(max(1, limit), EXPORT_AUDIT_MAX)
    stmt = select(AuditLog).where(AuditLog.org_id == org_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor_operator_id:
        stmt = stmt.where(AuditLog.actor_operator_id == actor_operator_id)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(cap)
    return [audit_summary(db, row) for row in db.scalars(stmt).all()]


def audit_log_csv_rows(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Flatten list-shaped summaries into CSV columns."""
    rows: list[dict[str, str]] = []
    for item in items:
        actor = item.get("actor") or {}
        context = item.get("context")
        rows.append(
            {
                "id": str(item["id"]),
                "created_at": str(item.get("created_at") or ""),
                "action": str(item.get("action") or ""),
                "actor_id": str(actor["id"]) if actor.get("id") is not None else "",
                "actor_email": str(actor.get("email") or ""),
                "actor_display_name": str(actor.get("display_name") or ""),
                "target_type": str(item.get("target_type") or ""),
                "target_id": str(item["target_id"]) if item.get("target_id") is not None else "",
                "context": json.dumps(context, default=str) if context is not None else "",
            }
        )
    return rows


def audit_log_json_safe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stringify UUIDs for `json.dumps` (same fields as list summaries)."""
    out: list[dict[str, Any]] = []
    for item in items:
        actor = item.get("actor")
        safe_actor = None
        if actor is not None:
            safe_actor = {
                "id": str(actor["id"]),
                "email": actor["email"],
                "display_name": actor["display_name"],
            }
        out.append(
            {
                "id": str(item["id"]),
                "actor": safe_actor,
                "action": item["action"],
                "target_type": item.get("target_type"),
                "target_id": str(item["target_id"]) if item.get("target_id") is not None else None,
                "context": item.get("context"),
                "created_at": item["created_at"],
            }
        )
    return out
