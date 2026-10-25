# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""ConnectorSecret CRUD, wrapping kestrel.secrets.crypto so callers never
handle raw ciphertext/nonce bytes directly, plus SecretRedactor -- scrubbing
declared secret fields from any object before it's logged, sent to an AI
provider, or returned via the API. Redaction is defense in depth alongside
encryption at rest, not a replacement for it (see ADR-0004).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorSecret
from kestrel.secrets.crypto import EnvKeyProvider, KeyProvider, decrypt_secret, encrypt_secret, secret_context

REDACTED_PLACEHOLDER = "***REDACTED***"


def connector_secret_context(row_id: uuid.UUID, field_name: str) -> bytes:
    """Associated data for one ``connector_secrets`` row: the field name is
    part of it, so relabelling a row's ``field_name`` also fails to decrypt."""
    return secret_context(ConnectorSecret.__tablename__, row_id, field_name)


def set_secret(
    session: Session,
    *,
    org_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
    field_name: str,
    plaintext_value: str,
    key_provider: KeyProvider | None = None,
) -> ConnectorSecret:
    key_provider = key_provider or EnvKeyProvider()

    existing = session.scalars(
        select(ConnectorSecret).where(
            ConnectorSecret.connector_instance_id == connector_instance_id,
            ConnectorSecret.field_name == field_name,
        )
    ).one_or_none()

    # The row id is part of the associated data, so it is fixed before encrypting.
    row_id = existing.id if existing is not None else uuid.uuid4()
    encrypted = encrypt_secret(key_provider, org_id, plaintext_value, context=connector_secret_context(row_id, field_name))

    if existing is None:
        row = ConnectorSecret(
            id=row_id,
            connector_instance_id=connector_instance_id,
            field_name=field_name,
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            key_version=encrypted.key_version,
        )
        session.add(row)
    else:
        existing.ciphertext = encrypted.ciphertext
        existing.nonce = encrypted.nonce
        existing.key_version = encrypted.key_version
        existing.updated_at = datetime.now(UTC)
        row = existing

    session.flush()
    return row


def get_secrets(
    session: Session,
    *,
    org_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
    key_provider: KeyProvider | None = None,
) -> dict[str, str]:
    """Returns {field_name: plaintext_value} for every secret stored
    against this connector instance -- the shape the Connector SDK's
    `authenticate(config, secrets)` expects."""
    key_provider = key_provider or EnvKeyProvider()
    rows = session.scalars(
        select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == connector_instance_id)
    ).all()
    return {
        row.field_name: decrypt_secret(
            key_provider,
            org_id,
            row.ciphertext,
            row.nonce,
            context=connector_secret_context(row.id, row.field_name),
            key_version=row.key_version,
        )
        for row in rows
    }


def list_configured_secret_fields(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
) -> list[str]:
    """Field names that have ciphertext rows — never decrypts or returns values."""
    rows = session.scalars(
        select(ConnectorSecret.field_name).where(ConnectorSecret.connector_instance_id == connector_instance_id)
    ).all()
    return sorted({str(name) for name in rows})


def delete_secrets(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
) -> list[str]:
    """Delete every stored secret for the instance; returns the field names removed."""
    rows = session.scalars(
        select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == connector_instance_id)
    ).all()
    removed = sorted({str(row.field_name) for row in rows})
    for row in rows:
        session.delete(row)
    session.flush()
    return removed


def redact(value: Any, secret_fields: set[str]) -> Any:
    """Recursively replaces any dict key in `secret_fields` with a
    placeholder. Safe to call on arbitrary nested structures (raw connector
    payloads, log records, AI prompts)."""
    if isinstance(value, dict):
        return {
            key: (REDACTED_PLACEHOLDER if key in secret_fields else redact(val, secret_fields)) for key, val in value.items()
        }
    if isinstance(value, list):
        return [redact(item, secret_fields) for item in value]
    return value
