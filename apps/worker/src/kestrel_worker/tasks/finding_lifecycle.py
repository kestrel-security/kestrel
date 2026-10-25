# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task: reopen findings whose mute or exception has expired.

Mutes always carry ``muted_until`` and exceptions may carry ``expires_at``,
but nothing else acts on either: the expiry queues in the API only *report*
them. Without this sweep an expired mute stays muted forever.

Per org, in its own transaction, under the org's ``POLICY_EVALUATION``
advisory lock so it cannot interleave with an evaluation reconciling the same
findings. Webhooks are enqueued only after that org's commit.
"""

from __future__ import annotations

import logging

from kestrel.db.locks import POLICY_EVALUATION, org_advisory_xact_lock
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.findings.lifecycle import reopen_expired_deferrals
from sqlalchemy import select

from kestrel_worker.celery_app import app
from kestrel_worker.tasks.webhooks import deliver_webhook

logger = logging.getLogger(__name__)


@app.task(name="kestrel.findings.reopen_expired_deferrals")
def reopen_expired_finding_deferrals() -> int:
    """Returns the number of findings reopened across every org."""
    session = get_sessionmaker()()
    reopened = 0
    try:
        for org_id in session.scalars(select(Organization.id)).all():
            webhook_delivery_ids: list = []
            try:
                org_advisory_xact_lock(session, org_id, POLICY_EVALUATION)
                result = reopen_expired_deferrals(session, org_id, webhook_delivery_ids=webhook_delivery_ids)
                session.commit()
            except Exception:
                # One org failing must not stop every other org's expiries.
                session.rollback()
                logger.exception("reopening expired mutes/exceptions failed for org %s", org_id)
                continue
            reopened += result.total
            for delivery_id in webhook_delivery_ids:
                deliver_webhook.delay(delivery_id=str(delivery_id))
        return reopened
    finally:
        session.close()
