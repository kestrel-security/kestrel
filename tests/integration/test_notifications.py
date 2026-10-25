# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Personal notifications end to end: the `/notifications` inbox API, the email
channel (queued in the transaction, sent after commit), and the watched-findings
digest.

Email goes through a recording fake transport, never SMTP. `KESTREL_SMTP_HOST`
is set only so the channel considers email configured.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.webhook import FINDING_RESOLVED, WebhookDelivery, WebhookDeliveryStatus
from kestrel.findings.watch_digest import DIGEST_SENT_ACTION, preview_watch_digest, send_due_watch_digests
from kestrel.findings.watchers import watch_finding
from kestrel.notifications import email as email_channel
from kestrel.notifications.dispatch import schedule_finding_notifications, schedule_webhook_failure_notifications
from kestrel.notifications.email import pending_notification_emails
from kestrel.notifications.email_transport import EmailResult
from kestrel.notifications.preferences import update_preferences
from kestrel.testing import api_client, make_operator, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.integration.test_api_factories import make_finding, make_webhook


class FakeTransport:
    configured = True

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, *, to: Sequence[str], subject: str, text_body: str, **_kwargs) -> EmailResult:
        self.sent.append({"to": list(to), "subject": subject, "text_body": text_body})
        return EmailResult(delivered=True, backend="fake")


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> FakeTransport:
    transport = FakeTransport()
    monkeypatch.setenv("KESTREL_SMTP_HOST", "smtp.invalid")
    monkeypatch.setenv("APP_URL", "https://kestrel.example.com")
    monkeypatch.setattr(email_channel, "_org_transport", lambda _org_id: transport)
    return transport


@pytest.fixture
def no_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KESTREL_SMTP_HOST", raising=False)


def _notification(db: Session, *, org_id: uuid.UUID, operator_id: uuid.UUID, read: bool = False):
    row = OperatorInAppNotification(
        id=uuid.uuid4(),
        org_id=org_id,
        operator_id=operator_id,
        kind="finding",
        event_type="finding.opened",
        title=f"Finding opened: {uuid.uuid4().hex[:6]}",
        body="high · test",
        severity="high",
        payload={},
        read_at=datetime.now(UTC) if read else None,
    )
    db.add(row)
    db.flush()
    return row


# -- inbox API ---------------------------------------------------------------


def test_list_is_scoped_to_the_calling_operator(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org, me = client.kestrel_org, client.kestrel_operator
    other = make_operator(db_session, org)
    mine = _notification(db_session, org_id=org.id, operator_id=me.id)
    _notification(db_session, org_id=org.id, operator_id=other.id)
    db_session.commit()

    body = client.get("/api/v1/notifications").json()

    assert [item["id"] for item in body["items"]] == [str(mine.id)]
    assert body["unread_count"] == 1
    assert body["next_cursor"] is None


def test_unread_only_filter_and_unread_count(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org, me = client.kestrel_org, client.kestrel_operator
    unread = _notification(db_session, org_id=org.id, operator_id=me.id)
    _notification(db_session, org_id=org.id, operator_id=me.id, read=True)
    db_session.commit()

    assert len(client.get("/api/v1/notifications").json()["items"]) == 2
    only_unread = client.get("/api/v1/notifications?unread_only=true").json()["items"]
    assert [item["id"] for item in only_unread] == [str(unread.id)]
    assert client.get("/api/v1/notifications/unread-count").json() == {"unread_count": 1}


def test_list_paginates_with_a_cursor(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org, me = client.kestrel_org, client.kestrel_operator
    ids = {str(_notification(db_session, org_id=org.id, operator_id=me.id).id) for _ in range(3)}
    db_session.commit()

    first = client.get("/api/v1/notifications?limit=2").json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]
    second = client.get(f"/api/v1/notifications?limit=2&cursor={first['next_cursor']}").json()
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None
    assert {item["id"] for item in first["items"] + second["items"]} == ids


def test_mark_one_read(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org, me = client.kestrel_org, client.kestrel_operator
    row = _notification(db_session, org_id=org.id, operator_id=me.id)
    db_session.commit()

    response = client.post(f"/api/v1/notifications/{row.id}/read")

    assert response.status_code == 200
    assert response.json()["is_read"] is True
    first_read_at = response.json()["read_at"]
    # Idempotent: a second call keeps the original timestamp.
    assert client.post(f"/api/v1/notifications/{row.id}/read").json()["read_at"] == first_read_at
    assert client.get("/api/v1/notifications/unread-count").json()["unread_count"] == 0


def test_cannot_mark_another_operators_notification(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    other = make_operator(db_session, org)
    theirs = _notification(db_session, org_id=org.id, operator_id=other.id)
    db_session.commit()

    assert client.post(f"/api/v1/notifications/{theirs.id}/read").status_code == 404
    db_session.refresh(theirs)
    assert theirs.read_at is None


def test_mark_all_read_only_touches_the_caller(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org, me = client.kestrel_org, client.kestrel_operator
    other = make_operator(db_session, org)
    _notification(db_session, org_id=org.id, operator_id=me.id)
    _notification(db_session, org_id=org.id, operator_id=me.id)
    theirs = _notification(db_session, org_id=org.id, operator_id=other.id)
    db_session.commit()

    assert client.post("/api/v1/notifications/read-all").json() == {"updated": 2, "unread_count": 0}
    db_session.refresh(theirs)
    assert theirs.read_at is None


def test_finding_events_reach_the_inbox_with_a_link(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.ANALYST)
    finding = make_finding(db_session, client.kestrel_org)
    db_session.commit()

    items = client.get("/api/v1/notifications").json()["items"]

    assert len(items) == 1
    assert items[0]["finding_id"] == str(finding.id)
    assert items[0]["detail_path"] == f"/findings/{finding.id}"


# -- email channel -----------------------------------------------------------


def test_finding_event_is_emailed_after_commit(db_session, smtp):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)

    finding = make_finding(db_session, org)

    assert smtp.sent == []  # nothing leaves before the commit
    assert len(pending_notification_emails(db_session)) == 1
    db_session.commit()

    assert len(smtp.sent) == 1
    message = smtp.sent[0]
    assert message["to"] == [operator.email]
    assert finding.title in message["subject"]
    assert f"https://kestrel.example.com/findings/{finding.id}" in message["text_body"]


def test_rollback_discards_queued_email(db_session, smtp):
    org = make_organization(db_session)
    make_operator(db_session, org)
    make_finding(db_session, org)

    db_session.rollback()
    db_session.commit()

    assert smtp.sent == []


def test_email_disabled_operator_gets_in_app_only(db_session, smtp):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    update_preferences(db_session, org_id=org.id, operator_id=operator.id, email_enabled=False)

    make_finding(db_session, org)
    db_session.commit()

    assert smtp.sent == []
    inbox = db_session.scalars(
        select(OperatorInAppNotification).where(OperatorInAppNotification.operator_id == operator.id)
    ).all()
    assert len(inbox) == 1


def test_nothing_is_queued_without_smtp(db_session, no_smtp):
    org = make_organization(db_session)
    make_operator(db_session, org)
    make_finding(db_session, org)

    assert pending_notification_emails(db_session) == []


def test_watcher_is_emailed_despite_finding_prefs(db_session, smtp):
    org = make_organization(db_session)
    watcher = make_operator(db_session, org)
    finding = make_finding(db_session, org)
    db_session.commit()
    smtp.sent.clear()
    update_preferences(db_session, org_id=org.id, operator_id=watcher.id, findings_enabled=False)
    watch_finding(db_session, org_id=org.id, operator_id=watcher.id, finding=finding)

    schedule_finding_notifications(db_session, org_id=org.id, event_type=FINDING_RESOLVED, finding=finding)
    db_session.commit()

    assert [m["to"] for m in smtp.sent] == [[watcher.email]]


def test_webhook_failure_is_emailed_to_admins_only(db_session, smtp):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    make_operator(db_session, org, role=OperatorRole.ANALYST)
    endpoint, _secret = make_webhook(db_session, org)
    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        event_type="finding.opened",
        payload={},
        status=WebhookDeliveryStatus.FAILED,
        attempt_count=1,
        error_message="HTTP 500",
    )
    db_session.add(delivery)
    db_session.flush()

    schedule_webhook_failure_notifications(db_session, delivery=delivery, endpoint=endpoint)
    db_session.commit()

    assert len(smtp.sent) == 1
    assert smtp.sent[0]["to"] == [operator.email]
    assert f"/settings/webhooks/{endpoint.id}" in smtp.sent[0]["text_body"]


def test_webhook_failure_email_never_carries_a_raw_html_error(db_session, smtp):
    # A row recorded before error summaries existed still holds the receiver's
    # HTML page; the notification shows only its text.
    org = make_organization(db_session)
    make_operator(db_session, org)
    endpoint, _secret = make_webhook(db_session, org)
    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        event_type="finding.opened",
        payload={},
        status=WebhookDeliveryStatus.FAILED,
        attempt_count=1,
        error_message="HTTP 503: <html><body><h1>Service\n\n Unavailable</h1></body></html>",
    )
    db_session.add(delivery)
    db_session.flush()

    schedule_webhook_failure_notifications(db_session, delivery=delivery, endpoint=endpoint)
    db_session.commit()

    assert "finding.opened · HTTP 503: Service Unavailable" in smtp.sent[0]["text_body"]
    assert "<h1>" not in smtp.sent[0]["text_body"]


def test_preferences_report_whether_email_is_configured(db_session, smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    assert client.get("/api/v1/notification-preferences").json()["email_configured"] is True


def test_preferences_report_email_unconfigured(db_session, no_smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    assert client.get("/api/v1/notification-preferences").json()["email_configured"] is False


# -- watched-findings digest -------------------------------------------------


def _watching_operator(db_session: Session):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    finding = make_finding(db_session, org)
    watch_finding(db_session, org_id=org.id, operator_id=operator.id, finding=finding)
    db_session.commit()
    return org, operator, finding


def test_digest_is_sent_once_per_window(db_session, smtp):
    _org, operator, finding = _watching_operator(db_session)
    smtp.sent.clear()
    now = datetime.now(UTC)

    assert send_due_watch_digests(db_session, transport=smtp, now=now) == 1
    assert smtp.sent[0]["to"] == [operator.email]
    assert "watched findings digest" in smtp.sent[0]["subject"]
    assert f"https://kestrel.example.com/findings/{finding.id}" in smtp.sent[0]["text_body"]
    db_session.commit()

    # The next hourly run inside the same window sends nothing more.
    assert send_due_watch_digests(db_session, transport=smtp, now=now + timedelta(hours=1)) == 0
    assert len(smtp.sent) == 1
    audit = db_session.scalars(
        select(AuditLog).where(AuditLog.action == DIGEST_SENT_ACTION, AuditLog.target_id == operator.id)
    ).all()
    assert len(audit) == 1


def test_digest_skips_operators_with_email_disabled(db_session, smtp):
    org, operator, _finding = _watching_operator(db_session)
    smtp.sent.clear()
    update_preferences(db_session, org_id=org.id, operator_id=operator.id, email_enabled=False)

    assert send_due_watch_digests(db_session, transport=smtp) == 0
    assert smtp.sent == []


def test_digest_preview_says_what_would_be_sent(db_session, smtp):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    finding = make_finding(db_session, client.kestrel_org)
    watch_finding(db_session, org_id=client.kestrel_org.id, operator_id=client.kestrel_operator.id, finding=finding)
    db_session.commit()
    smtp.sent.clear()

    body = client.post("/api/v1/findings/watched/digest-preview").json()

    assert body["would_send"] is True
    assert body["reason"] is None
    assert body["email_configured"] is True
    assert body["recipient"] == client.kestrel_operator.email
    assert body["summary"]["watched_total"] == 1
    assert smtp.sent == []  # a preview never sends


def test_digest_preview_explains_unconfigured_email(db_session, no_smtp):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)

    preview = preview_watch_digest(db_session, org_id=org.id, operator=operator)

    assert preview["would_send"] is False
    assert preview["reason"] == "email_not_configured"


def test_digest_task_does_nothing_without_smtp(db_session, no_smtp):
    _watching_operator(db_session)
    assert send_due_watch_digests(db_session) == 0
