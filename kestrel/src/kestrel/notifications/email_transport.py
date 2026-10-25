# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""SMTP email transport.

Shared path for personal notification email, watched-findings digests, and
dashboard schedules. The mail server comes from the organization's settings
(Settings -> Email, ``kestrel.notifications.smtp_settings``) or, without
them, the deployment-wide ``KESTREL_SMTP_*`` environment. When neither is set,
send() logs and returns ``delivered=False`` (backend ``"stub"``) without
raising.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import EmailMessage

from kestrel.env import getenv_bool
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_smtp_host

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailResult:
    delivered: bool
    backend: str
    detail: str | None = None


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    from_addr: str
    use_tls: bool
    use_ssl: bool
    # "org" (Settings -> Email) or "environment" (KESTREL_SMTP_*).
    source: str = "environment"
    # Re-check the host right before connecting. On for admin-entered hosts,
    # so a DNS change after saving cannot point mail at a metadata address.
    check_host: bool = False


def load_smtp_config() -> SmtpConfig | None:
    host = (os.environ.get("KESTREL_SMTP_HOST") or "").strip()
    if not host:
        return None
    port = int(os.environ.get("KESTREL_SMTP_PORT") or "587")
    from_addr = (os.environ.get("KESTREL_SMTP_FROM") or "").strip()
    if not from_addr:
        from_addr = "kestrel@localhost"
    return SmtpConfig(
        host=host,
        port=port,
        username=(os.environ.get("KESTREL_SMTP_USER") or "").strip() or None,
        password=os.environ.get("KESTREL_SMTP_PASSWORD") or None,
        from_addr=from_addr,
        use_tls=getenv_bool("KESTREL_SMTP_TLS", True),
        use_ssl=getenv_bool("KESTREL_SMTP_SSL", False),
    )


class EmailTransport:
    """Send email via SMTP; a logged no-op when unconfigured."""

    def __init__(self, config: SmtpConfig | None = None) -> None:
        self.config = config if config is not None else load_smtp_config()

    @property
    def configured(self) -> bool:
        return self.config is not None

    def send(
        self,
        *,
        to: Sequence[str],
        subject: str,
        text_body: str,
        html_body: str | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
    ) -> EmailResult:
        """attachments: list of (filename, content, mime_type)."""
        recipients = [a.strip() for a in to if a and a.strip()]
        if not recipients:
            return EmailResult(delivered=False, backend="none", detail="no recipients")
        if self.config is None:
            logger.info(
                "email_stub",
                extra={"subject": subject, "recipients": len(recipients)},
            )
            return EmailResult(
                delivered=False,
                backend="stub",
                detail="email is not configured",
            )

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.config.from_addr
        msg["To"] = ", ".join(recipients)
        msg.set_content(text_body)
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        for filename, content, mime in attachments or []:
            maintype, _, subtype = mime.partition("/")
            msg.add_attachment(
                content,
                maintype=maintype or "application",
                subtype=subtype or "octet-stream",
                filename=filename,
            )

        if self.config.check_host:
            try:
                validate_smtp_host(self.config.host)
            except UnsafeConnectorURLError as exc:
                logger.warning("smtp_host_refused", extra={"detail": str(exc)})
                return EmailResult(delivered=False, backend="smtp", detail=str(exc))

        try:
            # The stdlib defaults to an unverified context: no certificate
            # check, no hostname check. Credentials go over this connection.
            tls_context = ssl.create_default_context()
            if self.config.use_ssl:
                with smtplib.SMTP_SSL(self.config.host, self.config.port, timeout=30, context=tls_context) as smtp:
                    self._auth(smtp)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(self.config.host, self.config.port, timeout=30) as smtp:
                    if self.config.use_tls:
                        smtp.starttls(context=tls_context)
                    self._auth(smtp)
                    smtp.send_message(msg)
        except OSError as exc:  # includes smtplib.SMTPException
            logger.exception("smtp_send_failed")
            return EmailResult(delivered=False, backend="smtp", detail=_describe_smtp_error(exc))

        return EmailResult(delivered=True, backend="smtp", detail=None)

    def _auth(self, smtp: smtplib.SMTP) -> None:
        assert self.config is not None
        if self.config.username:
            smtp.login(self.config.username, self.config.password or "")


def _describe_smtp_error(exc: OSError) -> str:
    """A message an admin can act on, for the result's ``detail``."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "the mail server rejected the username or password"
    if isinstance(exc, smtplib.SMTPResponseException):
        message = exc.smtp_error.decode(errors="replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        return f"the mail server refused the message ({exc.smtp_code} {message})"
    return str(exc) or type(exc).__name__


def get_email_transport() -> EmailTransport:
    """The environment-configured transport, for callers with no organization."""
    return EmailTransport()
