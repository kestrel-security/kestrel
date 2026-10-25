# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Personal notification fan-out for finding lifecycle and webhook failures.

Two channels, each gated per operator by ``should_notify``:

- In-app: ``OperatorInAppNotification`` rows written in the caller's
  transaction, read through ``GET /notifications`` (the bell in the web UI).
- Email: queued on the session and sent after commit (``notifications.email``),
  only when SMTP is configured.

Finding delivery:
- Org-wide: every active operator whose prefs allow ``should_notify``.
- Watchers: subscribed operators also receive the event when prefs
  would otherwise suppress finding delivery; the channel switch
  (``in_app_enabled`` / ``email_enabled``) still wins. One delivery per
  operator per channel.

Webhook failure delivery:
- Fan-out when an outbound webhook delivery fails, gated by
  ``webhook_failures_enabled`` + channel. First attempt only
  (Celery retries do not re-notify).

Org outbound webhooks are unaffected by personal notifications.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED, WebhookDelivery, WebhookEndpoint
from kestrel.findings.watchers import watcher_operator_ids
from kestrel.notifications.email import queue_notification_email
from kestrel.notifications.preferences import get_or_create_preferences, should_notify
from kestrel.webhooks.errors import display_delivery_error

_EVENT_TITLES = {
    FINDING_OPENED: "Finding opened",
    FINDING_RESOLVED: "Finding resolved",
}

WEBHOOK_DELIVERY_FAILED = "webhook.delivery_failed"


def _finding_severity(finding: Finding) -> str:
    sev = finding.severity
    return sev.value if hasattr(sev, "value") else str(sev)


def finding_in_app_payload(
    *,
    event_type: str,
    finding: Finding,
    via_watch: bool = False,
) -> dict[str, Any]:
    return {
        "type": event_type,
        "created_at": datetime.now(UTC).isoformat(),
        "via_watch": via_watch,
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": _finding_severity(finding),
            "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
            "subject_type": (
                finding.subject_type.value if hasattr(finding.subject_type, "value") else str(finding.subject_type)
            ),
            "subject_id": str(finding.subject_id),
            "detail_path": f"/findings/{finding.id}",
        },
    }


def webhook_failure_in_app_payload(
    *,
    delivery: WebhookDelivery,
    endpoint: WebhookEndpoint,
) -> dict[str, Any]:
    detail_path = f"/settings/webhooks/{endpoint.id}"
    return {
        "type": WEBHOOK_DELIVERY_FAILED,
        "created_at": datetime.now(UTC).isoformat(),
        "detail_path": detail_path,
        "delivery": {
            "id": str(delivery.id),
            "event_type": delivery.event_type,
            "attempt_count": delivery.attempt_count,
            "http_status": delivery.http_status,
            "error_message": display_delivery_error(delivery.error_message),
            "finding_id": str(delivery.finding_id) if delivery.finding_id else None,
        },
        "endpoint": {
            "id": str(endpoint.id),
            "name": endpoint.name,
            "detail_path": detail_path,
        },
    }


def _insert_inbox_row(
    session: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    event_type: str,
    finding: Finding,
    severity: str,
    title: str,
    body: str,
    via_watch: bool,
) -> uuid.UUID:
    row_id = uuid.uuid4()
    session.add(
        OperatorInAppNotification(
            id=row_id,
            org_id=org_id,
            operator_id=operator_id,
            kind="finding",
            event_type=event_type,
            title=title[:512],
            body=body,
            finding_id=finding.id,
            severity=severity,
            payload=finding_in_app_payload(event_type=event_type, finding=finding, via_watch=via_watch),
            read_at=None,
        )
    )
    return row_id


def schedule_finding_notifications(
    session: Session,
    *,
    org_id: uuid.UUID,
    event_type: str,
    finding: Finding,
) -> list[uuid.UUID]:
    """Deliver a finding lifecycle event to every operator who should get it.

    Writes inbox rows (synchronous, no Celery) and queues email for after the
    commit. Call alongside ``schedule_finding_webhooks`` in the same transaction
    as the finding status change. Returns the new inbox row ids.
    """
    operators = session.scalars(
        select(Operator).where(
            Operator.org_id == org_id,
            Operator.is_active.is_(True),
        )
    ).all()
    if not operators:
        return []

    severity = _finding_severity(finding)
    title_prefix = _EVENT_TITLES.get(event_type, "Finding update")
    title = f"{title_prefix}: {finding.title}"
    body = f"{severity} · {finding.title}"
    detail_path = f"/findings/{finding.id}"
    watch_ids = set(watcher_operator_ids(session, org_id=org_id, finding_id=finding.id))

    created: list[uuid.UUID] = []
    for op in operators:
        prefs = get_or_create_preferences(session, org_id=org_id, operator_id=op.id)
        watching = op.id in watch_ids

        # Watching overrides the org-wide finding prefs (severity floor, muted
        # events, findings_enabled); the per-channel switch still wins.
        in_app_by_prefs = should_notify(prefs, channel="in_app", kind="finding", severity=severity, event_type=event_type)
        if in_app_by_prefs or (watching and prefs.in_app_enabled):
            created.append(
                _insert_inbox_row(
                    session,
                    org_id=org_id,
                    operator_id=op.id,
                    event_type=event_type,
                    finding=finding,
                    severity=severity,
                    title=title,
                    body=body,
                    via_watch=not in_app_by_prefs,
                )
            )

        email_by_prefs = should_notify(prefs, channel="email", kind="finding", severity=severity, event_type=event_type)
        if email_by_prefs or (watching and prefs.email_enabled):
            queue_notification_email(session, org_id=org_id, to=op.email, title=title, body=body, detail_path=detail_path)

    if created:
        session.flush()
    return created


def schedule_webhook_failure_notifications(
    session: Session,
    *,
    delivery: WebhookDelivery,
    endpoint: WebhookEndpoint,
) -> list[uuid.UUID]:
    """Notify admins when an outbound webhook delivery fails.

    Call after the delivery row is marked ``failed``. Notifies only on the first
    attempt so Celery retries do not spam anyone. Gated by operator
    ``webhook_failures_enabled`` plus the ``in_app`` / ``email`` channel.
    Returns the new inbox row ids.
    """
    if delivery.attempt_count != 1:
        return []

    # Webhook settings are admin-only, so only admins can act on (or open) the link.
    operators = session.scalars(
        select(Operator).where(
            Operator.org_id == delivery.org_id,
            Operator.is_active.is_(True),
            Operator.role == OperatorRole.ADMIN,
        )
    ).all()
    if not operators:
        return []

    title = f"Webhook delivery failed: {endpoint.name}"
    # Delivery records a concise summary; re-summarise anyway so a row written
    # before that (raw HTML error page) never reaches an inbox or email.
    err = display_delivery_error(delivery.error_message) or "delivery failed"
    body = f"{delivery.event_type} · {err}"[:2000]
    payload = webhook_failure_in_app_payload(delivery=delivery, endpoint=endpoint)

    detail_path = payload["detail_path"]

    created: list[uuid.UUID] = []
    for op in operators:
        prefs = get_or_create_preferences(session, org_id=delivery.org_id, operator_id=op.id)
        if should_notify(prefs, channel="email", kind="webhook_failure"):
            queue_notification_email(
                session, org_id=delivery.org_id, to=op.email, title=title, body=body, detail_path=detail_path
            )
        if not should_notify(prefs, channel="in_app", kind="webhook_failure"):
            continue
        row_id = uuid.uuid4()
        session.add(
            OperatorInAppNotification(
                id=row_id,
                org_id=delivery.org_id,
                operator_id=op.id,
                kind="webhook_failure",
                event_type=WEBHOOK_DELIVERY_FAILED,
                title=title[:512],
                body=body,
                finding_id=delivery.finding_id,
                severity=None,
                payload=payload,
                read_at=None,
            )
        )
        created.append(row_id)

    if created:
        session.flush()
    return created
