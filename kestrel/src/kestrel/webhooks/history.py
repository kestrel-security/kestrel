# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Webhook delivery history listing + manual retry.

Complements deliveries are created by dispatch and delivered by
Celery; this module exposes org-scoped history and admin re-drive for failed
or stuck pending rows.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint
from kestrel.webhooks.errors import display_delivery_error


class WebhookHistoryError(ValueError):
    """Invalid retry / history request."""


def _latency_ms(delivery: WebhookDelivery) -> int | None:
    """Wall-clock ms from enqueue to successful delivery (includes retries)."""
    if delivery.delivered_at is None or delivery.created_at is None:
        return None
    start = delivery.created_at
    end = delivery.delivered_at
    if start.tzinfo is None and end.tzinfo is not None:
        start = start.replace(tzinfo=end.tzinfo)
    elif end.tzinfo is None and start.tzinfo is not None:
        end = end.replace(tzinfo=start.tzinfo)
    delta = end - start
    ms = int(delta.total_seconds() * 1000)
    return max(0, ms)


def delivery_to_dict(delivery: WebhookDelivery) -> dict:
    return {
        "id": delivery.id,
        "webhook_endpoint_id": delivery.webhook_endpoint_id,
        "finding_id": delivery.finding_id,
        "event_type": delivery.event_type,
        "status": delivery.status.value,
        "attempt_count": delivery.attempt_count,
        "http_status": delivery.http_status,
        "error_message": display_delivery_error(delivery.error_message),
        "latency_ms": _latency_ms(delivery),
        "created_at": delivery.created_at.isoformat() if delivery.created_at else None,
        "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
        "can_retry": delivery.status in (WebhookDeliveryStatus.FAILED, WebhookDeliveryStatus.PENDING),
    }


def delivery_counts(session: Session, *, org_id: uuid.UUID, endpoint_id: uuid.UUID) -> dict[str, int]:
    rows = session.execute(
        select(WebhookDelivery.status, func.count())
        .where(
            WebhookDelivery.org_id == org_id,
            WebhookDelivery.webhook_endpoint_id == endpoint_id,
        )
        .group_by(WebhookDelivery.status)
    ).all()
    counts = {"pending": 0, "success": 0, "failed": 0}
    for status, count in rows:
        key = status.value if isinstance(status, WebhookDeliveryStatus) else str(status)
        if key in counts:
            counts[key] = int(count)
    return counts


def org_delivery_counts(session: Session, *, org_id: uuid.UUID) -> dict[str, int]:
    """Org-wide webhook delivery rollup for dashboard / SecOps queues.

    ``endpoints_with_failures`` counts distinct endpoints that have at least one
    failed delivery (so admins can see integration blast radius, not only row totals).
    """
    rows = session.execute(
        select(WebhookDelivery.status, func.count()).where(WebhookDelivery.org_id == org_id).group_by(WebhookDelivery.status)
    ).all()
    counts = {"pending": 0, "success": 0, "failed": 0}
    for status, count in rows:
        key = status.value if isinstance(status, WebhookDeliveryStatus) else str(status)
        if key in counts:
            counts[key] = int(count)

    endpoints_with_failures = (
        session.scalar(
            select(func.count(func.distinct(WebhookDelivery.webhook_endpoint_id))).where(
                WebhookDelivery.org_id == org_id,
                WebhookDelivery.status == WebhookDeliveryStatus.FAILED,
            )
        )
        or 0
    )
    return {
        **counts,
        "endpoints_with_failures": int(endpoints_with_failures),
    }


def _deliveries_query(
    *,
    org_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    status: WebhookDeliveryStatus | None,
) -> Select[tuple[WebhookDelivery]]:
    stmt = select(WebhookDelivery).where(
        WebhookDelivery.org_id == org_id,
        WebhookDelivery.webhook_endpoint_id == endpoint_id,
    )
    if status is not None:
        stmt = stmt.where(WebhookDelivery.status == status)
    return stmt.order_by(WebhookDelivery.created_at.desc())


def list_deliveries(
    session: Session,
    *,
    org_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    status: str | None = None,
    limit: int = 50,
) -> list[WebhookDelivery]:
    status_enum: WebhookDeliveryStatus | None = None
    if status is not None and status.strip():
        try:
            status_enum = WebhookDeliveryStatus(status.strip().lower())
        except ValueError as exc:
            raise WebhookHistoryError(f"invalid status {status!r}; expected pending, success, or failed") from exc

    capped = max(1, min(limit, 200))
    return list(
        session.scalars(_deliveries_query(org_id=org_id, endpoint_id=endpoint_id, status=status_enum).limit(capped)).all()
    )


def get_org_delivery(
    session: Session,
    *,
    org_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    delivery_id: uuid.UUID,
) -> WebhookDelivery | None:
    return session.scalar(
        select(WebhookDelivery).where(
            WebhookDelivery.id == delivery_id,
            WebhookDelivery.org_id == org_id,
            WebhookDelivery.webhook_endpoint_id == endpoint_id,
        )
    )


def retry_delivery(
    session: Session,
    *,
    org_id: uuid.UUID,
    endpoint: WebhookEndpoint,
    delivery_id: uuid.UUID,
) -> WebhookDelivery:
    """Marks a failed or stuck-pending delivery for another attempt.

    Leaves ``attempt_count`` intact (history of tries). Clears error / HTTP
    status so the next worker run starts clean. Successful deliveries cannot
    be retried (use a new finding event for a fresh payload).
    """
    delivery = get_org_delivery(session, org_id=org_id, endpoint_id=endpoint.id, delivery_id=delivery_id)
    if delivery is None:
        raise WebhookHistoryError("delivery not found")

    if delivery.status == WebhookDeliveryStatus.SUCCESS:
        raise WebhookHistoryError("successful deliveries cannot be retried")

    if not endpoint.is_enabled:
        raise WebhookHistoryError("webhook endpoint is disabled")

    delivery.status = WebhookDeliveryStatus.PENDING
    delivery.error_message = None
    delivery.http_status = None
    delivery.delivered_at = None
    session.flush()
    return delivery
