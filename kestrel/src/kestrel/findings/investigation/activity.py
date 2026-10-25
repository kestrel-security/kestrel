# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Newest-first investigation timeline for a finding: detection plus audit events."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.findings.investigation._common import _operator_out

ACTIVITY_TIMELINE_LIMIT = 50


_AUTO_TRANSITION_REASONS = {
    "policy_disabled": "policy disabled",
    "mute_expired": "mute expired",
    "exception_expired": "exception expired",
    "duplicate_merged": "merged into a newer finding for the same subject",
}


def _activity_summary(action: str, context: dict | None) -> str:
    ctx = context or {}
    if action == "finding.updated":
        parts: list[str] = []
        if "status" in ctx:
            parts.append(f"Status → {ctx['status']}")
        if "assigned_to_operator_id" in ctx:
            assignee = ctx["assigned_to_operator_id"]
            parts.append("Unassigned" if assignee is None else "Assignee updated")
        return "; ".join(parts) if parts else "Finding updated"
    if action in ("finding.auto_resolved", "finding.auto_reopened"):
        status = ctx.get("status") or ("resolved" if action == "finding.auto_resolved" else "open")
        reason = _AUTO_TRANSITION_REASONS.get(str(ctx.get("reason")), ctx.get("reason"))
        return f"Status → {status}{f' ({reason})' if reason else ''}"
    if action == "finding.exception_created":
        reason = ctx.get("reason")
        return f"Exception created{f': {reason}' if reason else ''}"
    if action == "finding.note_added":
        preview = ctx.get("body_preview") or ctx.get("body")
        if isinstance(preview, str) and preview.strip():
            trimmed = preview.strip()
            if len(trimmed) > 80:
                trimmed = trimmed[:77] + "…"
            return f"Note added: {trimmed}"
        return "Note added"
    if action == "finding.ticket_created":
        url = ctx.get("url")
        provider = ctx.get("provider")
        if isinstance(url, str) and url.strip():
            label = f" ({provider})" if isinstance(provider, str) and provider else ""
            return f"Ticket created{label}: {url.strip()}"
        return "Ticket created"
    return action


def activity_timeline(
    db: Session,
    finding: Finding,
    *,
    limit: int = ACTIVITY_TIMELINE_LIMIT,
) -> list[dict]:
    """Newest-first investigation timeline: first detection + audit events.

    Pipeline-opened findings may have no audit row; `finding.detected` is
    synthesized from `first_seen_at` so the workbench always has an anchor.
    """
    events: list[dict] = [
        {
            "at": finding.first_seen_at.isoformat(),
            "kind": "detected",
            "action": "finding.detected",
            "summary": "Finding first detected",
            "actor": None,
            "context": {"severity": finding.severity.value, "status": FindingStatus.OPEN.value},
        }
    ]

    audit_rows = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.org_id == finding.org_id,
            AuditLog.target_type == "finding",
            AuditLog.target_id == finding.id,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(max(limit - 1, 0))
    ).all()

    for row in audit_rows:
        events.append(
            {
                "at": row.created_at.isoformat() if row.created_at else finding.first_seen_at.isoformat(),
                "kind": "audit",
                "action": row.action,
                "summary": _activity_summary(row.action, row.context if isinstance(row.context, dict) else None),
                "actor": _operator_out(db, row.actor_operator_id),
                "context": row.context if isinstance(row.context, dict) else {},
            }
        )

    events.sort(key=lambda e: e["at"], reverse=True)
    return events[:limit]
