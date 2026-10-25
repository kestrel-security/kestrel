# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery tasks: personal notification email and watched-findings digests."""

from __future__ import annotations

from kestrel.db.session import get_sessionmaker
from kestrel.findings.watch_digest import send_due_watch_digests
from kestrel.notifications.email import NotificationEmail, send_notification_emails

from kestrel_worker.celery_app import app


@app.task(name="kestrel.notifications.send_watch_digests")
def send_watch_digests() -> int:
    session = get_sessionmaker()()
    try:
        sent = send_due_watch_digests(session)
        session.commit()
        return sent
    finally:
        session.close()


@app.task(name="kestrel.notifications.send_emails")
def send_emails(items: list[dict]) -> int:
    """Send notification email the API queued after its transaction committed."""
    return send_notification_emails(NotificationEmail(**item) for item in items)
