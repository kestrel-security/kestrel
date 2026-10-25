# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Deliver a single pending webhook over HTTP with SSRF re-check + HMAC signing."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint
from kestrel.notifications.dispatch import schedule_webhook_failure_notifications
from kestrel.observability.metrics import observe_webhook_delivery
from kestrel.observability.tracing import get_tracer
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url
from kestrel.webhooks.authoring import decrypt_endpoint_secret
from kestrel.webhooks.errors import summarize_http_failure
from kestrel.webhooks.signing import delivery_headers, sign_payload

logger = logging.getLogger(__name__)

DELIVERY_TIMEOUT_SECONDS = 10.0
USER_AGENT = "Kestrel-Webhooks/1.0"
#: Most of a receiver's error body that is ever read. Only a short excerpt is
#: kept, and a hostile receiver must not be able to stream gigabytes at us.
MAX_RESPONSE_BODY_BYTES = 64 * 1024


class WebhookDeliveryError(RuntimeError):
    """Non-success delivery (HTTP error, SSRF rejection, network failure).

    ``permanent`` says whether another attempt could succeed. A disabled or
    missing endpoint, an SSRF-rejected URL, and a receiver answering 4xx
    (other than 408/429) will fail the same way next time, so the worker does
    not retry them; transport errors, timeouts, throttles and 5xx are retried.
    """

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


def _is_permanent_http_failure(status_code: int) -> bool:
    return 400 <= status_code < 500 and status_code not in (408, 429)


def _read_capped(response: httpx.Response, limit: int = MAX_RESPONSE_BODY_BYTES) -> str:
    """At most ``limit`` bytes of a streamed response body, decoded leniently."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        chunks.append(chunk[: limit - size])
        size += len(chunks[-1])
        if size >= limit:
            break
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def _fail_delivery(
    session: Session,
    delivery: WebhookDelivery,
    endpoint: WebhookEndpoint | None,
    *,
    error_message: str,
    http_status: int | None = None,
    increment_attempt: bool = False,
) -> None:
    """Mark delivery failed, optionally notify operators (first attempt only)."""
    if increment_attempt:
        delivery.attempt_count += 1
    delivery.status = WebhookDeliveryStatus.FAILED
    delivery.error_message = error_message
    if http_status is not None:
        delivery.http_status = http_status
    session.flush()
    if endpoint is not None:
        schedule_webhook_failure_notifications(session, delivery=delivery, endpoint=endpoint)


def deliver_webhook_delivery(
    session: Session,
    delivery_id: uuid.UUID,
    *,
    http_client: httpx.Client | None = None,
) -> WebhookDelivery:
    """Performs one HTTP POST for a pending (or previously failed) delivery.
    Updates attempt_count / status on the row. Raises WebhookDeliveryError on
    failure so Celery can retry.
    """
    monotonic_started = time.monotonic()
    tracer = get_tracer("kestrel.webhooks")
    with tracer.start_as_current_span(
        "kestrel.webhook.deliver",
        attributes={"kestrel.webhook_delivery_id": str(delivery_id)},
    ) as span:
        try:
            delivery = _deliver_webhook_delivery_inner(session, delivery_id, http_client=http_client)
        except WebhookDeliveryError:
            observe_webhook_delivery(
                status=WebhookDeliveryStatus.FAILED.value,
                duration_seconds=time.monotonic() - monotonic_started,
            )
            span.set_attribute("kestrel.webhook.status", WebhookDeliveryStatus.FAILED.value)
            raise
        span.set_attribute("kestrel.webhook.status", delivery.status.value)
        if delivery.http_status is not None:
            span.set_attribute("http.status_code", delivery.http_status)
        observe_webhook_delivery(
            status=delivery.status.value,
            duration_seconds=time.monotonic() - monotonic_started,
        )
        return delivery


def _deliver_webhook_delivery_inner(
    session: Session,
    delivery_id: uuid.UUID,
    *,
    http_client: httpx.Client | None = None,
) -> WebhookDelivery:
    # The row lock is held until the caller commits, i.e. across the POST. A
    # duplicate task (broker redelivery, a manual retry racing the worker)
    # either finds the row locked and leaves it to the holder, or acquires it
    # afterwards and sees SUCCESS -- never a second POST of the same event.
    delivery = session.scalars(
        select(WebhookDelivery)
        .where(WebhookDelivery.id == delivery_id)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    ).one_or_none()
    if delivery is None:
        in_flight = session.get(WebhookDelivery, delivery_id)
        if in_flight is None:
            raise WebhookDeliveryError(f"delivery {delivery_id} not found", permanent=True)
        logger.info("webhook delivery already in progress elsewhere", extra={"delivery_id": str(delivery_id)})
        return in_flight
    if delivery.status == WebhookDeliveryStatus.SUCCESS:
        return delivery

    endpoint = session.get(WebhookEndpoint, delivery.webhook_endpoint_id)
    if endpoint is None or endpoint.org_id != delivery.org_id:
        _fail_delivery(
            session,
            delivery,
            None,
            error_message="webhook endpoint missing",
            increment_attempt=True,
        )
        raise WebhookDeliveryError(delivery.error_message or "webhook endpoint missing", permanent=True)

    if not endpoint.is_enabled:
        _fail_delivery(
            session,
            delivery,
            endpoint,
            error_message="webhook endpoint disabled",
            increment_attempt=True,
        )
        raise WebhookDeliveryError(delivery.error_message or "webhook endpoint disabled", permanent=True)

    delivery.attempt_count += 1

    try:
        # Same rule as create/update: no signed payloads over plaintext http
        # unless the host is explicitly allowlisted (rows saved before 0.4.0).
        validate_connector_url(endpoint.url, field="url", require_https=True)
    except UnsafeConnectorURLError as exc:
        _fail_delivery(session, delivery, endpoint, error_message=str(exc))
        raise WebhookDeliveryError(str(exc), permanent=True) from exc

    body = json.dumps(delivery.payload, separators=(",", ":"), default=str).encode("utf-8")
    secret = decrypt_endpoint_secret(endpoint)
    signature, timestamp = sign_payload(secret=secret, body=body)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        **delivery_headers(
            signature=signature,
            timestamp=timestamp,
            event_type=delivery.event_type,
            delivery_id=str(delivery.id),
        ),
    }

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=DELIVERY_TIMEOUT_SECONDS)
    try:
        with client.stream("POST", endpoint.url, content=body, headers=headers) as response:
            status_code = response.status_code
            # A success body is never used; an error body only as an excerpt.
            error_text = "" if 200 <= status_code < 300 else _read_capped(response)
    except httpx.HTTPError as exc:
        _fail_delivery(
            session,
            delivery,
            endpoint,
            error_message=f"transport error: {exc}",
        )
        raise WebhookDeliveryError(delivery.error_message or str(exc)) from exc
    finally:
        if owns_client:
            client.close()

    delivery.http_status = status_code
    if 200 <= status_code < 300:
        delivery.status = WebhookDeliveryStatus.SUCCESS
        delivery.error_message = None
        delivery.delivered_at = datetime.now(UTC)
        session.flush()
        logger.info(
            "webhook delivery succeeded",
            extra={
                "delivery_id": str(delivery.id),
                "endpoint_id": str(endpoint.id),
                "http_status": status_code,
            },
        )
        return delivery

    # Status plus a short tag-free excerpt, never the receiver's raw (often
    # HTML) error page: this string is shown in the deliveries table and in
    # failure notifications.
    _fail_delivery(
        session,
        delivery,
        endpoint,
        error_message=summarize_http_failure(status_code, error_text),
        http_status=status_code,
    )
    raise WebhookDeliveryError(
        delivery.error_message or f"HTTP {status_code}",
        permanent=_is_permanent_http_failure(status_code),
    )
