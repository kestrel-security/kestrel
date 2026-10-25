# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Watched-findings digest.

Operator-scoped summary of the findings they watch over a rolling window.
``send_due_watch_digests`` runs hourly from Celery beat and emails each
opted-in watcher at most once per window through the shared SMTP transport;
``preview_watch_digest`` returns what that run would send, without sending.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.audit.service import record_audit_event
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.operator import Operator
from kestrel.findings.listing import finding_summary
from kestrel.notifications.email import absolute_link, email_delivery_configured
from kestrel.notifications.email_transport import EmailTransport
from kestrel.notifications.preferences import get_or_create_preferences
from kestrel.notifications.smtp_settings import email_transport_for_org

logger = logging.getLogger(__name__)

DIGEST_KIND = "finding_watch_digest"
DIGEST_SENT_ACTION = "notification.watch_digest_sent"
DEFAULT_WINDOW_DAYS = 7
DUE_SLACK = timedelta(hours=1)
_AUDITED_COUNTS = ("watched_total", "still_open", "resolved_in_window", "activity_in_window")
OPENISH = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.MUTED,
        FindingStatus.EXCEPTION,
        FindingStatus.SUPPRESSED,
    }
)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def build_watch_digest(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    days: int = DEFAULT_WINDOW_DAYS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Digest for one operator's watches over a rolling window."""
    clock = now or datetime.now(UTC)
    window_days = max(1, min(int(days), 90))
    since = clock - timedelta(days=window_days)

    watches = list(
        db.scalars(
            select(FindingWatcher)
            .where(
                FindingWatcher.org_id == org_id,
                FindingWatcher.operator_id == operator_id,
            )
            .order_by(FindingWatcher.created_at.desc())
        ).all()
    )

    still_open: list[dict[str, Any]] = []
    resolved_in_window: list[dict[str, Any]] = []
    activity_in_window: list[dict[str, Any]] = []
    aging: list[dict[str, Any]] = []

    for watch in watches:
        finding = db.get(Finding, watch.finding_id)
        if finding is None or finding.org_id != org_id:
            continue
        summary = finding_summary(db, finding, now=clock)
        summary["watching"] = True
        summary["watched_at"] = watch.created_at.isoformat() if watch.created_at else None
        summary["detail_path"] = f"/findings/{finding.id}"
        # JSON-friendly ids
        row = {
            **summary,
            "id": str(summary["id"]),
            "subject_id": str(summary["subject_id"]),
            "policy_version_id": str(summary["policy_version_id"]),
            "assigned_to": (
                {**summary["assigned_to"], "id": str(summary["assigned_to"]["id"])} if summary.get("assigned_to") else None
            ),
        }

        resolved_at = _aware(finding.resolved_at)
        last_seen = _aware(finding.last_seen_at)
        first_seen = _aware(finding.first_seen_at)

        if finding.status == FindingStatus.RESOLVED and resolved_at and resolved_at >= since:
            resolved_in_window.append(row)
        elif finding.status in OPENISH:
            still_open.append(row)
            if last_seen and last_seen >= since:
                activity_in_window.append(row)
            if first_seen and (clock - first_seen).days >= window_days:
                aging.append(row)

    def _sev_rank(item: dict[str, Any]) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return order.get(str(item.get("severity") or ""), 9)

    still_open.sort(key=_sev_rank)
    resolved_in_window.sort(key=lambda r: r.get("resolved_at") or "", reverse=True)
    activity_in_window.sort(key=lambda r: r.get("last_seen_at") or "", reverse=True)
    aging.sort(key=lambda r: r.get("age_days") or 0, reverse=True)

    by_severity: dict[str, int] = {}
    for item in still_open:
        sev = str(item.get("severity") or "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    summary = {
        "watched_total": len(watches),
        "still_open": len(still_open),
        "resolved_in_window": len(resolved_in_window),
        "activity_in_window": len(activity_in_window),
        "aging_open": len(aging),
        "by_severity": by_severity,
        "window_days": window_days,
    }

    subject = "Kestrel watched findings digest"
    if still_open:
        subject = f"Kestrel watched findings digest — {len(still_open)} still open"
    elif resolved_in_window:
        subject = f"Kestrel watched findings digest — {len(resolved_in_window)} resolved in {window_days}d"

    lines = [
        f"Window: last {window_days} days",
        f"Watches: {summary['watched_total']}",
        f"Still open (incl. muted/exception/suppressed): {summary['still_open']}",
        f"Resolved in window: {summary['resolved_in_window']}",
        f"Open with activity (last_seen) in window: {summary['activity_in_window']}",
        f"Aging open (≥{window_days}d since first seen): {summary['aging_open']}",
        "",
    ]
    if by_severity:
        parts = ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items()))
        lines.append(f"Open by severity: {parts}")
        lines.append("")

    def _append_section(title: str, items: list[dict[str, Any]], *, limit: int = 15) -> None:
        if not items:
            return
        lines.append(f"{title}:")
        for item in items[:limit]:
            slug = f" · `{item.get('policy_slug')}`" if item.get("policy_slug") else ""
            link = absolute_link(item.get("detail_path"))
            lines.append(f"  - [{item.get('severity')}/{item.get('status')}] {item.get('title')}{slug} → {link}")
        if len(items) > limit:
            lines.append(f"  - … and {len(items) - limit} more")
        lines.append("")

    _append_section("Still open", still_open)
    _append_section("Resolved in window", resolved_in_window)
    _append_section("Activity in window", activity_in_window)
    _append_section("Aging open", aging)

    if not watches:
        lines.append("You are not watching any findings. Open a finding and choose Watch.")
        lines.append("")
    lines.append(
        "You receive this digest because you watch these findings and email is enabled in your "
        f"notification preferences ({absolute_link('/settings/notifications')})."
    )

    return {
        "as_of": clock.isoformat(),
        "kind": DIGEST_KIND,
        "window_days": window_days,
        "since": since.isoformat(),
        "subject": subject,
        "body_text": "\n".join(lines).rstrip() + "\n",
        "summary": summary,
        "still_open": still_open,
        "resolved_in_window": resolved_in_window,
        "activity_in_window": activity_in_window,
        "aging_open": aging,
        "href": "/settings/notifications",
    }


def has_changes(digest: dict[str, Any]) -> bool:
    """Whether a digest reports anything that happened inside its window."""
    summary = digest["summary"]
    return bool(summary["resolved_in_window"] or summary["activity_in_window"])


def last_digest_sent_at(db: Session, *, org_id: uuid.UUID, operator_id: uuid.UUID) -> datetime | None:
    """When this operator was last sent a digest (from the audit trail)."""
    sent = db.scalar(
        select(func.max(AuditLog.created_at)).where(
            AuditLog.org_id == org_id,
            AuditLog.action == DIGEST_SENT_ACTION,
            AuditLog.target_type == "operator",
            AuditLog.target_id == operator_id,
        )
    )
    return _aware(sent)


def digest_due(last_sent: datetime | None, *, now: datetime, window_days: int = DEFAULT_WINDOW_DAYS) -> bool:
    """One digest per window. The slack absorbs the hourly beat tick drifting
    a few minutes later each run, which would otherwise push a weekly digest
    an hour later every week."""
    if last_sent is None:
        return True
    return now - last_sent >= timedelta(days=window_days) - DUE_SLACK


def _send_decision(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator: Operator,
    digest: dict[str, Any],
    email_configured: bool,
    now: datetime,
) -> tuple[bool, str | None, datetime | None]:
    """``(would_send, reason, last_sent_at)``; ``reason`` explains a ``False``."""
    last_sent = last_digest_sent_at(db, org_id=org_id, operator_id=operator.id)
    prefs = get_or_create_preferences(db, org_id=org_id, operator_id=operator.id)
    if not email_configured:
        return False, "email_not_configured", last_sent
    if not prefs.email_enabled:
        return False, "email_disabled", last_sent
    if not (operator.email or "").strip():
        return False, "no_email_address", last_sent
    if not digest["summary"]["watched_total"]:
        return False, "no_watches", last_sent
    if not has_changes(digest):
        return False, "no_changes", last_sent
    if not digest_due(last_sent, now=now, window_days=digest["window_days"]):
        return False, "already_sent_this_window", last_sent
    return True, None, last_sent


def preview_watch_digest(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator: Operator,
    days: int = DEFAULT_WINDOW_DAYS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The digest the calling operator would be emailed, and whether the next
    scheduled run would send it. Sends nothing."""
    clock = now or datetime.now(UTC)
    digest = build_watch_digest(db, org_id=org_id, operator_id=operator.id, days=days, now=clock)
    configured = email_delivery_configured(db, org_id)
    would_send, reason, last_sent = _send_decision(
        db, org_id=org_id, operator=operator, digest=digest, email_configured=configured, now=clock
    )
    return {
        **digest,
        "email_configured": configured,
        "would_send": would_send,
        "reason": reason,
        "recipient": operator.email,
        "last_sent_at": last_sent.isoformat() if last_sent else None,
    }


def send_due_watch_digests(
    db: Session,
    *,
    transport: EmailTransport | None = None,
    now: datetime | None = None,
) -> int:
    """Email every opted-in watcher whose digest is due. Returns emails delivered.

    Opted in means: watching at least one finding, active, has an email
    address, and ``email_enabled`` in their preferences. Watching is itself the
    opt-in, so the org-wide finding filters (severity floor, muted events) do
    not apply here, as with per-event watcher delivery. A digest with nothing
    resolved or active in its window is skipped. Each send is recorded as a
    ``notification.watch_digest_sent`` audit event, which is also what makes
    the hourly run send at most one digest per window. Each organization's
    digests go through its own mail server; one without email is skipped.
    Does not commit.
    """
    clock = now or datetime.now(UTC)

    watcher_rows = db.execute(select(FindingWatcher.org_id, FindingWatcher.operator_id).distinct()).all()
    mailers: dict[uuid.UUID, EmailTransport] = {}
    sent = 0
    for org_id, operator_id in watcher_rows:
        if org_id not in mailers:
            mailers[org_id] = transport or email_transport_for_org(db, org_id)
        mailer = mailers[org_id]
        if not mailer.configured:
            continue
        operator = db.get(Operator, operator_id)
        if operator is None or not operator.is_active or operator.org_id != org_id:
            continue
        digest = build_watch_digest(db, org_id=org_id, operator_id=operator_id, now=clock)
        would_send, _reason, _last = _send_decision(
            db, org_id=org_id, operator=operator, digest=digest, email_configured=True, now=clock
        )
        if not would_send:
            continue
        result = mailer.send(to=[operator.email], subject=digest["subject"], text_body=digest["body_text"])
        if not result.delivered:
            logger.warning(
                "watch_digest_not_delivered",
                extra={"operator_id": str(operator_id), "backend": result.backend, "detail": result.detail},
            )
            continue
        record_audit_event(
            db,
            org_id=org_id,
            actor_operator_id=None,
            action=DIGEST_SENT_ACTION,
            target_type="operator",
            target_id=operator_id,
            context={"window_days": digest["window_days"], **{k: digest["summary"][k] for k in _AUDITED_COUNTS}},
        )
        db.flush()
        sent += 1
    return sent
