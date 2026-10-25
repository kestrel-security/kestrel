# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org mail server (SMTP) settings: authoring and resolution.

An admin sets the server at Settings -> Email. A saved, enabled row wins;
otherwise email falls back to the deployment-wide ``KESTREL_SMTP_*``
environment (``email_transport.load_smtp_config``), so a deployment that
configured email that way keeps sending.
"""

from __future__ import annotations

import uuid
from email.utils import parseaddr
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.smtp_settings import (
    DEFAULT_PORTS,
    SECURITY_NONE,
    SECURITY_SSL,
    SECURITY_STARTTLS,
    SMTP_SECURITY_MODES,
    OrgSmtpSettings,
)
from kestrel.notifications.email_transport import EmailTransport, SmtpConfig, load_smtp_config
from kestrel.secrets.crypto import (
    EnvKeyProvider,
    KeyProvider,
    MissingMasterKeyError,
    decrypt_secret,
    encrypt_secret,
    secret_context,
)
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_smtp_host

SOURCE_ORG = "org"
SOURCE_ENVIRONMENT = "environment"


class SmtpSettingsError(ValueError):
    """Invalid mail server settings input."""


def validate_host(host: str) -> str:
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned or len(cleaned) > 253:
        raise SmtpSettingsError("host must be 1–253 characters")
    try:
        validate_smtp_host(cleaned)
    except UnsafeConnectorURLError as exc:
        raise SmtpSettingsError(str(exc)) from exc
    return cleaned


def validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise SmtpSettingsError("port must be between 1 and 65535")
    return port


def validate_security(security: str) -> str:
    cleaned = security.strip().lower()
    if cleaned not in SMTP_SECURITY_MODES:
        raise SmtpSettingsError(f"security must be one of: {', '.join(sorted(SMTP_SECURITY_MODES))}")
    return cleaned


def validate_from_address(from_address: str) -> str:
    cleaned = from_address.strip()
    _name, address = parseaddr(cleaned)
    if not address or "@" not in address or len(cleaned) > 320 or "\n" in cleaned or "\r" in cleaned:
        raise SmtpSettingsError("from_address must be an email address, e.g. kestrel@example.com")
    return cleaned


def _clean_username(username: str | None) -> str | None:
    cleaned = (username or "").strip()
    if len(cleaned) > 320:
        raise SmtpSettingsError("username is too long")
    return cleaned or None


def smtp_password_context(row_id: uuid.UUID) -> bytes:
    """Associated data binding the SMTP password to its settings row."""
    return secret_context(OrgSmtpSettings.__tablename__, row_id, "password")


def get_org_smtp_settings(session: Session, org_id: uuid.UUID) -> OrgSmtpSettings | None:
    return session.scalar(select(OrgSmtpSettings).where(OrgSmtpSettings.org_id == org_id))


def upsert_org_smtp_settings(
    session: Session,
    *,
    org_id: uuid.UUID,
    host: str,
    port: int,
    security: str,
    from_address: str,
    username: str | None = None,
    password: str | None = None,
    is_enabled: bool = True,
    key_provider: KeyProvider | None = None,
) -> tuple[OrgSmtpSettings, bool]:
    """Create or update the org's mail server. Returns ``(row, password_changed)``.

    ``password`` blank keeps the stored one -- unless the host, port or
    username changes, in which case a stored password must be entered again
    (it is never sent to a server it was not entered for). Credentials are
    refused with ``security="none"``: they would cross the network in clear.
    """
    host_name = validate_host(host)
    port_number = validate_port(port)
    mode = validate_security(security)
    sender = validate_from_address(from_address)
    user = _clean_username(username)
    new_password = password if password is not None and password.strip() else None
    if new_password is not None and len(new_password) > 1024:
        raise SmtpSettingsError("password is too long")
    if mode == SECURITY_NONE and (user or new_password):
        raise SmtpSettingsError(
            "a username and password need STARTTLS or SSL/TLS; with security 'none' they would be sent unencrypted"
        )
    if new_password is not None and user is None:
        raise SmtpSettingsError("a password needs a username")

    row = get_org_smtp_settings(session, org_id)
    if row is None:
        row = OrgSmtpSettings(id=uuid.uuid4(), org_id=org_id)
        session.add(row)
    elif row.password_ciphertext is not None and new_password is None and user is not None:
        moved = (row.host, row.port, row.username) != (host_name, port_number, user)
        if moved:
            raise SmtpSettingsError(
                "password is required when changing the host, port or username "
                "(the stored password is not sent to a different server or account)"
            )

    row.host = host_name
    row.port = port_number
    row.security = mode
    row.from_address = sender
    row.username = user
    row.is_enabled = is_enabled
    if user is None:
        row.password_ciphertext = None
        row.password_nonce = None
        row.password_key_version = None
    elif new_password is not None:
        kp = key_provider or EnvKeyProvider()
        encrypted = encrypt_secret(kp, org_id, new_password, context=smtp_password_context(row.id))
        row.password_ciphertext = encrypted.ciphertext
        row.password_nonce = encrypted.nonce
        row.password_key_version = encrypted.key_version
    return row, new_password is not None


def clear_org_smtp_settings(session: Session, org_id: uuid.UUID) -> bool:
    row = get_org_smtp_settings(session, org_id)
    if row is None:
        return False
    session.delete(row)
    return True


def _org_config(row: OrgSmtpSettings, key_provider: KeyProvider | None) -> SmtpConfig | None:
    password = None
    if row.password_ciphertext is not None and row.password_nonce is not None and row.password_key_version is not None:
        try:
            kp = key_provider or EnvKeyProvider()
            password = decrypt_secret(
                kp,
                row.org_id,
                row.password_ciphertext,
                row.password_nonce,
                context=smtp_password_context(row.id),
                key_version=row.password_key_version,
            )
        except MissingMasterKeyError:
            return None
    return SmtpConfig(
        host=row.host,
        port=row.port,
        username=row.username,
        password=password,
        from_addr=row.from_address,
        use_tls=row.security == SECURITY_STARTTLS,
        use_ssl=row.security == SECURITY_SSL,
        source=SOURCE_ORG,
        check_host=True,
    )


def resolve_smtp_config(
    session: Session | None,
    org_id: uuid.UUID | None,
    *,
    key_provider: KeyProvider | None = None,
) -> SmtpConfig | None:
    """The mail server in force: the org's enabled settings, else the environment, else None."""
    if session is not None and org_id is not None:
        row = get_org_smtp_settings(session, org_id)
        if row is not None and row.is_enabled:
            config = _org_config(row, key_provider)
            if config is not None:
                return config
    return load_smtp_config()


def email_transport_for_org(session: Session | None, org_id: uuid.UUID | None) -> EmailTransport:
    """A transport for the org's mail server. Unconfigured, it is the logged no-op
    (``EmailTransport(None)`` re-reads the environment, which is unset too)."""
    return EmailTransport(config=resolve_smtp_config(session, org_id))


def _security_of(config: SmtpConfig) -> str:
    if config.use_ssl:
        return SECURITY_SSL
    return SECURITY_STARTTLS if config.use_tls else SECURITY_NONE


def settings_out(row: OrgSmtpSettings | None, in_force: SmtpConfig | None) -> dict[str, Any]:
    """Status for the settings page -- never a password, stored or from the environment."""
    org = None
    if row is not None:
        org = {
            "host": row.host,
            "port": row.port,
            "security": row.security,
            "username": row.username,
            "password_configured": row.password_ciphertext is not None,
            "from_address": row.from_address,
            "is_enabled": row.is_enabled,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
    if in_force is None:
        return {
            "source": None,
            "configured": False,
            "host": None,
            "port": None,
            "security": None,
            "username": None,
            "password_configured": False,
            "from_address": None,
            "is_enabled": False,
            "updated_at": None,
            "org": org,
            "default_ports": dict(DEFAULT_PORTS),
        }
    from_org = in_force.source == SOURCE_ORG
    return {
        "source": SOURCE_ORG if from_org else SOURCE_ENVIRONMENT,
        "configured": True,
        "host": in_force.host,
        "port": in_force.port,
        "security": _security_of(in_force),
        "username": in_force.username,
        "password_configured": bool(in_force.password),
        "from_address": in_force.from_addr,
        "is_enabled": True,
        "updated_at": org["updated_at"] if from_org and org else None,
        "org": org,
        "default_ports": dict(DEFAULT_PORTS),
    }


__all__ = [
    "SOURCE_ENVIRONMENT",
    "SOURCE_ORG",
    "SmtpSettingsError",
    "clear_org_smtp_settings",
    "email_transport_for_org",
    "get_org_smtp_settings",
    "resolve_smtp_config",
    "settings_out",
    "upsert_org_smtp_settings",
    "validate_from_address",
    "validate_host",
    "validate_port",
    "validate_security",
]
