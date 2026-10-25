# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Personal notification email channel.

Finding lifecycle and webhook-failure fan-out (``notifications.dispatch``) runs
inside the caller's transaction, so an email must not leave before that
transaction commits: a rolled-back finding change would otherwise have already
been announced. Dispatch therefore *queues* messages on the SQLAlchemy session
(``session.info``) and an ``after_commit`` listener hands them on;
``after_rollback`` discards them. By default they go straight through the
shared SMTP ``EmailTransport``. The API instead registers a dispatcher
(``use_email_dispatcher``) that enqueues them for the worker, so a slow SMTP
server never holds up a request.

Everything queued by one commit is grouped per recipient, so a sync that opens
forty findings sends each operator one email listing them, not forty.

The mail server is the organization's (Settings -> Email) or, without one, the
``KESTREL_SMTP_*`` environment; see ``notifications.smtp_settings``. When
neither is set nothing is queued.
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from sqlalchemy import event
from sqlalchemy.orm import Session

from kestrel.db.session import get_sessionmaker
from kestrel.notifications.email_transport import EmailTransport
from kestrel.notifications.smtp_settings import email_transport_for_org, resolve_smtp_config

logger = logging.getLogger(__name__)

_PENDING_KEY = "kestrel.notifications.pending_email"
_DISPATCH_KEY = "kestrel.notifications.email_dispatch"
_CONFIGURED_KEY = "kestrel.notifications.email_configured"
# Lines listed per email before collapsing the rest into "... and N more".
MAX_ITEMS_PER_EMAIL = 25


@dataclass(frozen=True)
class NotificationEmail:
    """One event for one recipient. Plain data: it outlives the session."""

    org_id: str
    to: str
    title: str
    body: str | None
    detail_path: str | None


def email_delivery_configured(session: Session | None, org_id: uuid.UUID | None) -> bool:
    """Whether the organization can send email at all (its own mail server or the environment's)."""
    return resolve_smtp_config(session, org_id) is not None


def app_url() -> str | None:
    """Public origin for absolute links in email, from ``APP_URL``."""
    value = (os.environ.get("APP_URL") or "").strip().rstrip("/")
    return value or None


def absolute_link(path: str | None, *, base_url: str | None = None) -> str | None:
    if not path:
        return None
    base = base_url if base_url is not None else app_url()
    return f"{base}{path}" if base else path


def queue_notification_email(
    session: Session,
    *,
    org_id: uuid.UUID,
    to: str | None,
    title: str,
    body: str | None,
    detail_path: str | None,
) -> bool:
    """Queue one notification for delivery after ``session`` commits.

    Returns False (and queues nothing) when the organization has no mail
    server or the operator has no email address.
    """
    address = (to or "").strip()
    if not address:
        return False
    configured: dict[uuid.UUID, bool] = session.info.setdefault(_CONFIGURED_KEY, {})
    if org_id not in configured:
        configured[org_id] = email_delivery_configured(session, org_id)
    if not configured[org_id]:
        return False
    pending: list[NotificationEmail] = session.info.setdefault(_PENDING_KEY, [])
    pending.append(NotificationEmail(org_id=str(org_id), to=address, title=title, body=body, detail_path=detail_path))
    return True


def pending_notification_emails(session: Session) -> list[NotificationEmail]:
    """What the next commit on ``session`` will send (for tests and debugging)."""
    return list(session.info.get(_PENDING_KEY, []))


def render_notification_email(
    items: list[NotificationEmail],
    *,
    base_url: str | None = None,
) -> tuple[str, str]:
    """Subject and plain-text body for one recipient's batch."""
    if not items:
        raise ValueError("no notifications to render")
    subject = f"[Kestrel] {items[0].title}" if len(items) == 1 else f"[Kestrel] {len(items)} new notifications"

    lines: list[str] = []
    for item in items[:MAX_ITEMS_PER_EMAIL]:
        lines.append(f"- {item.title}")
        if item.body:
            lines.append(f"  {item.body}")
        link = absolute_link(item.detail_path, base_url=base_url)
        if link:
            lines.append(f"  {link}")
    if len(items) > MAX_ITEMS_PER_EMAIL:
        lines.append(f"- ... and {len(items) - MAX_ITEMS_PER_EMAIL} more in Kestrel")
    lines.append("")
    settings_link = absolute_link("/settings/notifications", base_url=base_url)
    lines.append(f"You receive these because email is enabled in your notification preferences ({settings_link}).")
    return subject, "\n".join(lines) + "\n"


def _org_transport(org_id: str) -> EmailTransport:
    with get_sessionmaker()() as session:
        return email_transport_for_org(session, uuid.UUID(org_id))


def send_notification_emails(
    items: Iterable[NotificationEmail],
    *,
    transport: EmailTransport | None = None,
    transport_for: Callable[[str], EmailTransport] | None = None,
) -> int:
    """Send one email per recipient, through each organization's mail server.
    Returns how many were delivered.

    Never raises: a failed send is logged, and the change that triggered it
    has already committed.
    """
    by_recipient: dict[tuple[str, str], list[NotificationEmail]] = {}
    for item in items:
        by_recipient.setdefault((item.org_id, item.to), []).append(item)
    if not by_recipient:
        return 0

    mailers: dict[str, EmailTransport] = {}
    delivered = 0
    for (org_id, to), batch in by_recipient.items():
        subject, text = render_notification_email(batch)
        try:
            mailer = (
                transport or mailers.get(org_id) or mailers.setdefault(org_id, (transport_for or _org_transport)(org_id))
            )
        except Exception:
            logger.exception("notification_email_transport_failed")
            continue
        try:
            result = mailer.send(to=[to], subject=subject, text_body=text)
        except Exception:
            logger.exception("notification_email_failed")
            continue
        if result.delivered:
            delivered += 1
        else:
            logger.warning("notification_email_not_delivered", extra={"backend": result.backend, "detail": result.detail})
    return delivered


EmailDispatcher = Callable[[list[NotificationEmail]], object]


def use_email_dispatcher(session: Session, dispatch: EmailDispatcher) -> None:
    """Hand the emails each commit on ``session`` releases to ``dispatch``
    instead of sending them inline."""
    session.info[_DISPATCH_KEY] = dispatch


@event.listens_for(Session, "after_commit")
def _send_after_commit(session: Session) -> None:
    session.info.pop(_CONFIGURED_KEY, None)
    pending = session.info.pop(_PENDING_KEY, None)
    if pending:
        dispatch: EmailDispatcher = session.info.get(_DISPATCH_KEY, send_notification_emails)
        dispatch(pending)


@event.listens_for(Session, "after_rollback")
def _discard_after_rollback(session: Session) -> None:
    session.info.pop(_CONFIGURED_KEY, None)
    session.info.pop(_PENDING_KEY, None)
