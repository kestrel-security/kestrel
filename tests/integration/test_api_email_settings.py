# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- Settings -> Email: the org mail server, its API, and its use.

Hosts are IP literals so the host guard never needs DNS.
"""

from __future__ import annotations

import uuid

import pytest
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import OperatorRole
from kestrel.notifications import email as email_channel
from kestrel.notifications.email_transport import EmailResult
from kestrel.notifications.smtp_settings import resolve_smtp_config
from kestrel.testing import api_client
from kestrel_api.routers import email_settings as email_router
from sqlalchemy import select

SETTINGS = {
    "host": "10.20.30.40",
    "port": 587,
    "security": "starttls",
    "from_address": "Kestrel <kestrel@example.com>",
    "username": "mailer",
    "password": "relay-password-123",
}


@pytest.fixture(autouse=True)
def no_env_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("KESTREL_SMTP_HOST", "KESTREL_SMTP_USER", "KESTREL_SMTP_PASSWORD", "KESTREL_SMTP_FROM"):
        monkeypatch.delenv(name, raising=False)


def _actions(db_session, org_id) -> list[str]:
    return list(db_session.scalars(select(AuditLog.action).where(AuditLog.org_id == org_id)).all())


def test_saving_returns_the_settings_but_never_the_password(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    put = client.put("/api/v1/settings/email", json=SETTINGS)

    assert put.status_code == 200, put.text
    assert "relay-password-123" not in put.text
    body = put.json()
    assert body["source"] == "org"
    assert body["host"] == "10.20.30.40"
    assert body["password_configured"] is True
    assert body["org"]["username"] == "mailer"
    assert "relay-password-123" not in client.get("/api/v1/settings/email").text
    assert "settings.email_updated" in _actions(db_session, client.kestrel_org.id)

    config = resolve_smtp_config(db_session, client.kestrel_org.id)
    assert config is not None
    assert config.password == "relay-password-123"
    assert config.check_host


def test_the_environment_is_reported_and_used_without_saved_settings(db_session, monkeypatch):
    monkeypatch.setenv("KESTREL_SMTP_HOST", "smtp.env.example")
    monkeypatch.setenv("KESTREL_SMTP_PASSWORD", "env-secret")
    client = api_client(db_session, OperatorRole.ADMIN)

    body = client.get("/api/v1/settings/email").json()

    assert body["source"] == "environment"
    assert body["host"] == "smtp.env.example"
    assert body["org"] is None
    assert "env-secret" not in str(body)


def test_saved_settings_override_the_environment_until_cleared_or_disabled(db_session, monkeypatch):
    monkeypatch.setenv("KESTREL_SMTP_HOST", "smtp.env.example")
    client = api_client(db_session, OperatorRole.ADMIN)
    client.put("/api/v1/settings/email", json=SETTINGS)
    org_id = client.kestrel_org.id

    assert resolve_smtp_config(db_session, org_id).source == "org"
    client.put("/api/v1/settings/email", json={**SETTINGS, "password": None, "is_enabled": False})
    assert resolve_smtp_config(db_session, org_id).source == "environment"
    assert client.delete("/api/v1/settings/email").json() == {"cleared": True}
    assert resolve_smtp_config(db_session, org_id).source == "environment"
    assert "settings.email_cleared" in _actions(db_session, org_id)


def test_a_stored_password_must_be_reentered_for_a_different_server(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    client.put("/api/v1/settings/email", json=SETTINGS)

    moved = client.put("/api/v1/settings/email", json={**SETTINGS, "host": "10.20.30.41", "password": None})
    kept = client.put("/api/v1/settings/email", json={**SETTINGS, "from_address": "ops@example.com", "password": ""})

    assert moved.status_code == 400
    assert "password is required" in moved.json()["detail"]
    assert kept.status_code == 200
    assert resolve_smtp_config(db_session, client.kestrel_org.id).password == "relay-password-123"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"host": "169.254.169.254"}, "link-local"),
        ({"security": "none"}, "unencrypted"),
        ({"port": 0}, "port"),
        ({"from_address": "not-an-address"}, "from_address"),
        ({"security": "carrier-pigeon"}, "security"),
    ],
)
def test_unsafe_or_invalid_settings_are_refused(db_session, change, message):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.put("/api/v1/settings/email", json={**SETTINGS, **change})

    assert response.status_code == 400
    assert message in response.json()["detail"]


def test_no_credentials_with_security_none_clears_the_stored_password(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    client.put("/api/v1/settings/email", json=SETTINGS)

    body = client.put(
        "/api/v1/settings/email",
        json={**SETTINGS, "security": "none", "port": 25, "username": None, "password": None},
    ).json()

    assert body["password_configured"] is False
    assert resolve_smtp_config(db_session, client.kestrel_org.id).password is None


def test_send_test_email_reports_the_outcome_and_audits_it(db_session, monkeypatch):
    sent: list[dict] = []

    def fake_send(self, **kwargs) -> EmailResult:
        sent.append({"host": self.config.host, **kwargs})
        return EmailResult(delivered=True, backend="smtp")

    monkeypatch.setattr(email_router.EmailTransport, "send", fake_send)
    client = api_client(db_session, OperatorRole.ADMIN)

    assert client.post("/api/v1/settings/email/test").json()["ok"] is False  # nothing configured
    client.put("/api/v1/settings/email", json=SETTINGS)
    result = client.post("/api/v1/settings/email/test").json()

    assert result == {"ok": True, "source": "org", "to": client.kestrel_operator.email, "detail": None}
    assert sent[0]["host"] == "10.20.30.40"
    assert sent[0]["to"] == [client.kestrel_operator.email]
    assert "settings.email_tested" in _actions(db_session, client.kestrel_org.id)


def test_org_settings_alone_turn_email_on_for_notifications(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    assert client.get("/api/v1/notification-preferences").json()["email_configured"] is False

    client.put("/api/v1/settings/email", json=SETTINGS)

    assert client.get("/api/v1/notification-preferences").json()["email_configured"] is True
    assert email_channel.queue_notification_email(
        db_session, org_id=client.kestrel_org.id, to="a@example.com", title="t", body=None, detail_path=None
    )
    db_session.rollback()


def test_notification_emails_go_through_each_orgs_own_server(db_session):
    first = api_client(db_session, OperatorRole.ADMIN)
    second = api_client(db_session, OperatorRole.ADMIN)
    first.put("/api/v1/settings/email", json=SETTINGS)
    second.put("/api/v1/settings/email", json={**SETTINGS, "host": "10.9.9.9"})
    hosts: list[str] = []

    class _Recorder:
        def __init__(self, host: str) -> None:
            self.host = host

        def send(self, **_kwargs) -> EmailResult:
            hosts.append(self.host)
            return EmailResult(delivered=True, backend="fake")

    def transport_for(org_id: str):
        config = resolve_smtp_config(db_session, uuid.UUID(org_id))
        return _Recorder(config.host)

    items = [
        email_channel.NotificationEmail(str(first.kestrel_org.id), "a@example.com", "t", None, None),
        email_channel.NotificationEmail(str(second.kestrel_org.id), "a@example.com", "t", None, None),
    ]

    assert email_channel.send_notification_emails(items, transport_for=transport_for) == 2
    assert sorted(hosts) == ["10.20.30.40", "10.9.9.9"]
