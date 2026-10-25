# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- notification email rendering, per-recipient batching, and the
watched-digest cadence. Pure logic over a fake transport; no DB, no SMTP."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.findings.watch_digest import digest_due, has_changes
from kestrel.notifications.email import (
    MAX_ITEMS_PER_EMAIL,
    NotificationEmail,
    render_notification_email,
    send_notification_emails,
)
from kestrel.notifications.email_transport import EmailResult

_ORG = "00000000-0000-0000-0000-000000000001"


class FakeTransport:
    configured = True

    def __init__(self, *, delivered: bool = True, raises: bool = False) -> None:
        self.sent: list[dict] = []
        self._delivered = delivered
        self._raises = raises

    def send(self, *, to: Sequence[str], subject: str, text_body: str, **_kwargs) -> EmailResult:
        if self._raises:
            raise RuntimeError("smtp exploded")
        self.sent.append({"to": list(to), "subject": subject, "text_body": text_body})
        return EmailResult(delivered=self._delivered, backend="fake")


def _item(to: str = "a@example.com", n: int = 1) -> NotificationEmail:
    return NotificationEmail(
        org_id=_ORG, to=to, title=f"Finding opened: thing {n}", body="high · thing", detail_path=f"/findings/{n}"
    )


def test_single_item_subject_is_the_event_title() -> None:
    subject, body = render_notification_email([_item()], base_url="https://k.example")
    assert subject == "[Kestrel] Finding opened: thing 1"
    assert "https://k.example/findings/1" in body
    assert "https://k.example/settings/notifications" in body


def test_multiple_items_are_counted_and_capped() -> None:
    items = [_item(n=i) for i in range(MAX_ITEMS_PER_EMAIL + 3)]
    subject, body = render_notification_email(items, base_url="https://k.example")
    assert subject == f"[Kestrel] {MAX_ITEMS_PER_EMAIL + 3} new notifications"
    assert "... and 3 more" in body
    assert f"thing {MAX_ITEMS_PER_EMAIL}" not in body


def test_relative_links_without_app_url() -> None:
    _subject, body = render_notification_email([_item()], base_url="")
    assert "  /findings/1" in body


def test_render_rejects_an_empty_batch() -> None:
    with pytest.raises(ValueError, match="no notifications to render"):
        render_notification_email([])


def test_one_email_per_recipient() -> None:
    transport = FakeTransport()
    items = [_item("a@example.com", 1), _item("b@example.com", 2), _item("a@example.com", 3)]

    delivered = send_notification_emails(items, transport=transport)  # type: ignore[arg-type]

    assert delivered == 2
    assert sorted(m["to"][0] for m in transport.sent) == ["a@example.com", "b@example.com"]
    to_a = next(m for m in transport.sent if m["to"] == ["a@example.com"])
    assert to_a["subject"] == "[Kestrel] 2 new notifications"


def test_send_failures_never_raise() -> None:
    assert send_notification_emails([_item()], transport=FakeTransport(raises=True)) == 0  # type: ignore[arg-type]
    assert send_notification_emails([_item()], transport=FakeTransport(delivered=False)) == 0  # type: ignore[arg-type]


def test_nothing_to_send() -> None:
    transport = FakeTransport()
    assert send_notification_emails([], transport=transport) == 0  # type: ignore[arg-type]
    assert transport.sent == []


NOW = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("last_sent", "due"),
    [
        (None, True),
        (NOW - timedelta(days=1), False),
        (NOW - timedelta(days=7), True),
        # Beat drift: an hourly tick landing a few minutes early still counts.
        (NOW - timedelta(days=7) + timedelta(minutes=10), True),
        (NOW - timedelta(days=6, hours=20), False),
    ],
)
def test_digest_due(last_sent: datetime | None, due: bool) -> None:
    assert digest_due(last_sent, now=NOW, window_days=7) is due


@pytest.mark.parametrize(
    ("resolved", "activity", "expected"),
    [(0, 0, False), (1, 0, True), (0, 2, True)],
)
def test_has_changes(resolved: int, activity: int, expected: bool) -> None:
    digest = {"summary": {"resolved_in_window": resolved, "activity_in_window": activity}}
    assert has_changes(digest) is expected


def _commit_with_pending(dispatch=None) -> list[list[NotificationEmail]]:
    from kestrel.notifications import email as email_channel
    from sqlalchemy.orm import Session

    handed_off: list[list[NotificationEmail]] = []
    session = Session()
    if dispatch is None:
        email_channel.use_email_dispatcher(session, handed_off.append)
    else:
        email_channel.use_email_dispatcher(session, dispatch)
    session.info["kestrel.notifications.pending_email"] = [_item()]
    session.commit()
    return handed_off


def test_commit_hands_pending_email_to_the_session_dispatcher() -> None:
    assert _commit_with_pending() == [[_item()]]


def test_api_dispatcher_enqueues_a_worker_task(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_api import tasks_client

    sent: list[tuple[str, dict]] = []

    class FakeCelery:
        def send_task(self, name: str, kwargs: dict) -> None:
            sent.append((name, kwargs))

    monkeypatch.setattr(tasks_client, "get_celery_client", lambda: FakeCelery())
    tasks_client.enqueue_notification_emails([_item()])

    assert sent == [("kestrel.notifications.send_emails", {"items": [_item().__dict__]})]


def test_api_dispatcher_survives_a_broker_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_api import tasks_client

    def broken() -> None:
        raise ConnectionError("redis down")

    monkeypatch.setattr(tasks_client, "get_celery_client", broken)
    tasks_client.enqueue_notification_emails([_item()])  # logs, does not raise


def test_worker_task_sends_what_the_api_enqueued(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel.notifications import email as email_channel
    from kestrel_worker.tasks import notifications as task_module

    transport = FakeTransport()
    monkeypatch.setattr(email_channel, "_org_transport", lambda _org_id: transport)

    assert task_module.send_emails([_item().__dict__]) == 1
    assert transport.sent[0]["to"] == ["a@example.com"]
