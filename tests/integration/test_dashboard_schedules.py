# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard email schedules: what a scheduled run actually sends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from kestrel.dashboard import boards as boards_svc
from kestrel.dashboard import schedules as schedules_svc
from kestrel.db.models.dashboard import DashboardSchedule
from kestrel.db.models.operator import OperatorRole
from kestrel.notifications.email_transport import EmailResult
from kestrel.testing import make_operator, make_organization
from sqlalchemy.orm import Session


@dataclass
class _RecordingTransport:
    sent: list[dict[str, Any]] = field(default_factory=list)

    def send(self, **kwargs: Any) -> EmailResult:
        self.sent.append(kwargs)
        return EmailResult(delivered=True, backend="smtp", detail=None)


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> _RecordingTransport:
    recorder = _RecordingTransport()
    monkeypatch.setattr(schedules_svc, "email_transport_for_org", lambda _db, _org_id: recorder)
    return recorder


def _schedule(db_session: Session, fmt: str) -> DashboardSchedule:
    org = make_organization(db_session)
    admin = make_operator(db_session, org, role=OperatorRole.ADMIN)
    board = boards_svc.create_dashboard(db_session, org_id=org.id, operator=admin, name="Scheduled board")
    created = schedules_svc.create_schedule(
        db_session,
        org_id=org.id,
        dashboard_id=board["id"],
        operator=admin,
        cron="0 9 * * *",
        fmt=fmt,
        recipient_operator_ids=[str(admin.id)],
    )
    schedule = db_session.get(DashboardSchedule, created["id"])
    assert schedule is not None
    return schedule


def test_an_html_schedule_sends_one_email_with_the_export_inline_and_attached(
    db_session: Session, transport: _RecordingTransport
) -> None:
    # A run used to send the HTML export twice: once as an attachment with no
    # HTML body, then again as a second email with the HTML as its body.
    result = schedules_svc.run_schedule(db_session, _schedule(db_session, "html"))

    assert result["ok"] is True
    assert len(transport.sent) == 1
    (email,) = transport.sent
    assert email["html_body"]
    assert "Scheduled board" in email["html_body"]
    ((filename, _payload, mime),) = email["attachments"]
    assert filename.endswith(".html")
    assert mime == "text/html"


def test_a_json_schedule_sends_one_email_with_only_an_attachment(
    db_session: Session, transport: _RecordingTransport
) -> None:
    schedules_svc.run_schedule(db_session, _schedule(db_session, "json"))

    assert len(transport.sent) == 1
    assert transport.sent[0]["html_body"] is None
    ((filename, _payload, mime),) = transport.sent[0]["attachments"]
    assert filename.endswith(".json")
    assert mime == "application/json"
