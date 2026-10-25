# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Schedule outbound webhook deliveries for finding lifecycle events.

Creates ``WebhookDelivery`` rows in the caller's transaction. Callers must
``enqueue_webhook_deliveries`` *after* commit so Celery never races a
rolled-back row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint


def finding_webhook_payload(*, event_type: str, finding: Finding, delivery_id: uuid.UUID) -> dict:
    return {
        "id": str(delivery_id),
        "type": event_type,
        "created_at": datetime.now(UTC).isoformat(),
        "data": {
            "finding": {
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "subject_type": finding.subject_type.value,
                "subject_id": str(finding.subject_id),
                "policy_version_id": str(finding.policy_version_id),
                "first_seen_at": finding.first_seen_at.isoformat(),
                "last_seen_at": finding.last_seen_at.isoformat(),
                "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
            }
        },
    }


def schedule_finding_webhooks(
    session: Session,
    *,
    org_id: uuid.UUID,
    event_type: str,
    finding: Finding,
    delivery_ids: list[uuid.UUID] | None = None,
) -> list[uuid.UUID]:
    """Creates pending deliveries for every enabled endpoint subscribed to
    ``event_type``. Returns the new delivery ids (also appended to
    ``delivery_ids`` when provided).
    """
    endpoints = session.scalars(
        select(WebhookEndpoint).where(
            WebhookEndpoint.org_id == org_id,
            WebhookEndpoint.is_enabled.is_(True),
        )
    ).all()

    created: list[uuid.UUID] = []
    for endpoint in endpoints:
        subscribed = endpoint.events or []
        if event_type not in subscribed:
            continue
        delivery_id = uuid.uuid4()
        payload = finding_webhook_payload(event_type=event_type, finding=finding, delivery_id=delivery_id)
        session.add(
            WebhookDelivery(
                id=delivery_id,
                org_id=org_id,
                webhook_endpoint_id=endpoint.id,
                finding_id=finding.id,
                event_type=event_type,
                payload=payload,
                status=WebhookDeliveryStatus.PENDING,
                attempt_count=0,
            )
        )
        created.append(delivery_id)
        if delivery_ids is not None:
            delivery_ids.append(delivery_id)

    if created:
        session.flush()
    return created
