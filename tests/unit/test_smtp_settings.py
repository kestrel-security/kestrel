# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 1 -- mail server host guard and SMTP transport failure handling."""

from __future__ import annotations

import smtplib

import pytest
from kestrel.notifications.email_transport import EmailTransport, SmtpConfig
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_smtp_host


@pytest.mark.parametrize("host", ["10.0.0.5", "192.168.1.20", "127.0.0.1", "::1", "93.184.216.34"])
def test_private_loopback_and_public_relays_are_allowed(host: str) -> None:
    validate_smtp_host(host)


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "168.63.129.16", "100.100.100.200", "fe80::1", "224.0.0.1", "0.0.0.0"],
)
def test_metadata_link_local_and_multicast_are_refused(host: str) -> None:
    with pytest.raises(UnsafeConnectorURLError):
        validate_smtp_host(host)


@pytest.mark.parametrize("host", ["", "smtp.example.com/path", "user@smtp.example.com", "smtp.example.com:25", "a b"])
def test_anything_but_a_bare_host_is_refused(host: str) -> None:
    with pytest.raises(UnsafeConnectorURLError):
        validate_smtp_host(host)


def _config(**overrides) -> SmtpConfig:
    values = {
        "host": "10.0.0.5",
        "port": 587,
        "username": "mailer",
        "password": "secret",
        "from_addr": "kestrel@example.com",
        "use_tls": True,
        "use_ssl": False,
    }
    values.update(overrides)
    return SmtpConfig(**values)


class _RefusingSmtp:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self) -> _RefusingSmtp:
        return self

    def __exit__(self, *_exc) -> None:
        return None

    def starttls(self, *, context=None) -> None:
        return None

    def login(self, _user: str, _password: str) -> None:
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication failed")


def test_rejected_credentials_come_back_as_a_failed_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smtplib, "SMTP", _RefusingSmtp)

    result = EmailTransport(config=_config()).send(to=["a@example.com"], subject="s", text_body="b")

    assert result.delivered is False
    assert result.detail == "the mail server rejected the username or password"


def test_an_org_host_is_checked_again_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    def _never(*_args, **_kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr(smtplib, "SMTP", _never)

    result = EmailTransport(config=_config(host="169.254.169.254", check_host=True, source="org")).send(
        to=["a@example.com"], subject="s", text_body="b"
    )

    assert result.delivered is False
    assert "link-local" in (result.detail or "")
