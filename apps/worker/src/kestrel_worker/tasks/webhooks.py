# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task that POSTs one signed webhook delivery."""

from __future__ import annotations

import logging
import uuid

from kestrel.db.session import get_sessionmaker
from kestrel.webhooks.delivery import WebhookDeliveryError, deliver_webhook_delivery

from kestrel_worker.celery_app import app

logger = logging.getLogger(__name__)


def default_retry_delay_for(retries: int) -> int:
    """Exponential backoff from 30 seconds, doubling per attempt."""
    return 30 * (2 ** max(0, int(retries)))


@app.task(name="kestrel.webhooks.deliver", bind=True, max_retries=5, default_retry_delay=30)
def deliver_webhook(self, *, delivery_id: str) -> str:
    """Delivers one WebhookDelivery row. Returns status value on success."""
    session = get_sessionmaker()()
    try:
        delivery = deliver_webhook_delivery(session, uuid.UUID(delivery_id))
        session.commit()
        return delivery.status.value
    except WebhookDeliveryError as exc:
        session.commit()  # persist failed attempt_count / error_message
        if exc.permanent:
            # Same outcome next time (disabled endpoint, rejected URL, 4xx):
            # the row already says FAILED and operators were notified.
            logger.warning("webhook delivery failed permanently: %s", exc)
            return "failed"
        # 30s, 60s, 120s, 240s, 480s: a receiver that is briefly down gets a
        # few minutes, not five pokes inside three minutes.
        countdown = min(default_retry_delay_for(self.request.retries), 600)
        logger.warning("webhook delivery failed (retry in %ss): %s", countdown, exc)
        raise self.retry(exc=exc, countdown=countdown) from exc
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
