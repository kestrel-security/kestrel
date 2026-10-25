# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task wrapping kestrel.findings.pipeline.evaluate_all_enabled_policies
-- runs every enabled policy for an org and reconciles Findings. Called
directly (same session) as part of a sync in tasks/sync.py, and also
exposed as its own task for standalone re-evaluation (e.g. right after
installing a new pack, or a manual "re-run policies" trigger from the API).
"""

from __future__ import annotations

import uuid

from kestrel.db.session import get_sessionmaker
from kestrel.findings.pipeline import evaluate_all_enabled_policies

from kestrel_worker.celery_app import app
from kestrel_worker.tasks.webhooks import deliver_webhook


@app.task(name="kestrel.findings.evaluate_policies", bind=True, max_retries=3, default_retry_delay=30)
def evaluate_policies(self, *, org_id: str, connector_run_id: str | None = None) -> int:
    """Returns the number of PolicyEvaluations performed."""
    session = get_sessionmaker()()
    try:
        webhook_delivery_ids: list = []
        evaluations = evaluate_all_enabled_policies(
            session,
            org_id=uuid.UUID(org_id),
            connector_run_id=uuid.UUID(connector_run_id) if connector_run_id else None,
            webhook_delivery_ids=webhook_delivery_ids,
        )
        session.commit()
        for delivery_id in webhook_delivery_ids:
            deliver_webhook.delay(delivery_id=str(delivery_id))
        return len(evaluations)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
