# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Re-encrypt every stored secret under the current master key.

``SECRET_LOCATIONS`` is the single list of columns that hold ciphertext. Each
row carries the id of the master key that wrote it; :func:`rotate_all` walks
every location and re-encrypts the rows whose key id differs from the current
one, legacy (version 0, no associated data) rows included. It is idempotent
and safe to run while the API and worker are up: a row re-encrypted by a
request in the meantime simply reads as current and is skipped.

Driven by ``kestrel secrets status`` / ``kestrel secrets rotate``.
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.audit.service import record_audit_event
from kestrel.db.models.connector import ConnectorInstance, ConnectorSecret
from kestrel.db.models.llm_settings import OrgLlmSettings
from kestrel.db.models.operator import Operator
from kestrel.db.models.smtp_settings import OrgSmtpSettings
from kestrel.db.models.ticket import TicketIntegration
from kestrel.db.models.webhook import WebhookEndpoint
from kestrel.secrets.crypto import (
    LEGACY_KEY_VERSION,
    KeyProvider,
    UnknownKeyVersionError,
    decrypt_secret,
    encrypt_secret,
    secret_context,
)

logger = logging.getLogger(__name__)

ROTATION_AUDIT_ACTION = "secrets.rotated"


@dataclass(frozen=True)
class SecretLocation:
    """One ciphertext-bearing column and how to address it."""

    model: type[Any]
    field: str
    ciphertext_attr: str
    nonce_attr: str
    key_version_attr: str
    org_id_of: Callable[[Session, Any], uuid.UUID]

    @property
    def table(self) -> str:
        return str(self.model.__tablename__)

    def context(self, row: Any) -> bytes:
        return secret_context(self.table, row.id, self.field)

    def has_secret(self, row: Any) -> bool:
        return getattr(row, self.ciphertext_attr) is not None


def _own_org(_session: Session, row: Any) -> uuid.UUID:
    return row.org_id


def _connector_secret_org(session: Session, row: ConnectorSecret) -> uuid.UUID:
    org_id = session.scalar(select(ConnectorInstance.org_id).where(ConnectorInstance.id == row.connector_instance_id))
    if org_id is None:
        raise LookupError(f"connector_secrets {row.id} has no connector instance")
    return org_id


def _connector_secret_context(row: ConnectorSecret) -> bytes:
    return secret_context(ConnectorSecret.__tablename__, row.id, row.field_name)


class _ConnectorSecretLocation(SecretLocation):
    """connector_secrets binds the per-row ``field_name`` instead of a fixed field."""

    def context(self, row: Any) -> bytes:
        return _connector_secret_context(row)


SECRET_LOCATIONS: tuple[SecretLocation, ...] = (
    _ConnectorSecretLocation(
        model=ConnectorSecret,
        field="<field_name>",
        ciphertext_attr="ciphertext",
        nonce_attr="nonce",
        key_version_attr="key_version",
        org_id_of=_connector_secret_org,
    ),
    SecretLocation(
        model=WebhookEndpoint,
        field="secret",
        ciphertext_attr="secret_ciphertext",
        nonce_attr="secret_nonce",
        key_version_attr="secret_key_version",
        org_id_of=_own_org,
    ),
    SecretLocation(
        model=TicketIntegration,
        field="secret",
        ciphertext_attr="secret_ciphertext",
        nonce_attr="secret_nonce",
        key_version_attr="secret_key_version",
        org_id_of=_own_org,
    ),
    SecretLocation(
        model=OrgLlmSettings,
        field="secret",
        ciphertext_attr="secret_ciphertext",
        nonce_attr="secret_nonce",
        key_version_attr="secret_key_version",
        org_id_of=_own_org,
    ),
    SecretLocation(
        model=Operator,
        field="mfa_secret",
        ciphertext_attr="mfa_secret_ciphertext",
        nonce_attr="mfa_secret_nonce",
        key_version_attr="mfa_secret_key_version",
        org_id_of=_own_org,
    ),
    SecretLocation(
        model=OrgSmtpSettings,
        field="password",
        ciphertext_attr="password_ciphertext",
        nonce_attr="password_nonce",
        key_version_attr="password_key_version",
        org_id_of=_own_org,
    ),
)


@dataclass
class RotationStatus:
    current_key_version: int
    known_key_versions: tuple[int, ...]
    rows_by_key_version: dict[int, int] = field(default_factory=dict)
    rows_by_table: dict[str, int] = field(default_factory=dict)

    @property
    def total_rows(self) -> int:
        return sum(self.rows_by_key_version.values())

    @property
    def legacy_rows(self) -> int:
        return self.rows_by_key_version.get(LEGACY_KEY_VERSION, 0)

    @property
    def stale_rows(self) -> int:
        """Rows not written with the current key (legacy rows included)."""
        return sum(count for version, count in self.rows_by_key_version.items() if version != self.current_key_version)

    @property
    def unreadable_rows(self) -> int:
        """Rows under a key id this process does not hold."""
        return sum(
            count
            for version, count in self.rows_by_key_version.items()
            if version != LEGACY_KEY_VERSION and version not in self.known_key_versions
        )


@dataclass
class RotationFailure:
    table: str
    row_id: uuid.UUID
    error: str


@dataclass
class RotationReport:
    current_key_version: int
    rotated: int = 0
    rotated_by_table: dict[str, int] = field(default_factory=dict)
    failed: list[RotationFailure] = field(default_factory=list)
    dry_run: bool = False


def rotation_status(session: Session, key_provider: KeyProvider) -> RotationStatus:
    status = RotationStatus(
        current_key_version=key_provider.current_key_version,
        known_key_versions=key_provider.candidate_key_versions(),
    )
    by_version: Counter[int] = Counter()
    by_table: Counter[str] = Counter()
    for location in SECRET_LOCATIONS:
        version_col = getattr(location.model, location.key_version_attr)
        ciphertext_col = getattr(location.model, location.ciphertext_attr)
        rows = session.execute(
            select(version_col, func.count()).where(ciphertext_col.is_not(None)).group_by(version_col)
        ).all()
        for version, count in rows:
            if version is None:
                continue
            by_version[int(version)] += int(count)
            by_table[location.table] += int(count)
    status.rows_by_key_version = dict(sorted(by_version.items()))
    status.rows_by_table = dict(sorted(by_table.items()))
    return status


def rotate_all(
    session: Session,
    key_provider: KeyProvider,
    *,
    batch_size: int = 200,
    dry_run: bool = False,
) -> RotationReport:
    """Re-encrypt every row not written with the current key.

    Commits after each batch so a long rotation never holds one transaction
    open across every table. Rows that cannot be decrypted (unknown key id,
    tampered ciphertext) are reported in ``failed`` and left untouched; the
    rest of the rotation continues.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    current = key_provider.current_key_version
    report = RotationReport(current_key_version=current, dry_run=dry_run)
    rotated_per_org: dict[uuid.UUID, Counter[str]] = defaultdict(Counter)

    for location in SECRET_LOCATIONS:
        model = location.model
        version_col = getattr(model, location.key_version_attr)
        ciphertext_col = getattr(model, location.ciphertext_attr)
        skip: set[uuid.UUID] = set()
        while True:
            stmt = (
                select(model).where(ciphertext_col.is_not(None), version_col != current).order_by(model.id).limit(batch_size)
            )
            if skip:
                stmt = stmt.where(model.id.not_in(skip))
            if not dry_run:
                stmt = stmt.with_for_update(skip_locked=True)
            rows = session.scalars(stmt).all()
            if not rows:
                break
            for row in rows:
                try:
                    org_id = location.org_id_of(session, row)
                    plaintext = decrypt_secret(
                        key_provider,
                        org_id,
                        getattr(row, location.ciphertext_attr),
                        getattr(row, location.nonce_attr),
                        context=location.context(row),
                        key_version=int(getattr(row, location.key_version_attr)),
                    )
                except (InvalidTag, UnknownKeyVersionError, LookupError) as exc:
                    skip.add(row.id)
                    report.failed.append(RotationFailure(location.table, row.id, f"{type(exc).__name__}: {exc}"))
                    logger.warning("secrets rotate: cannot re-encrypt %s %s: %s", location.table, row.id, exc)
                    continue
                if dry_run:
                    skip.add(row.id)
                else:
                    encrypted = encrypt_secret(key_provider, org_id, plaintext, context=location.context(row))
                    setattr(row, location.ciphertext_attr, encrypted.ciphertext)
                    setattr(row, location.nonce_attr, encrypted.nonce)
                    setattr(row, location.key_version_attr, encrypted.key_version)
                report.rotated += 1
                report.rotated_by_table[location.table] = report.rotated_by_table.get(location.table, 0) + 1
                rotated_per_org[org_id][location.table] += 1
            if not dry_run:
                session.flush()
                session.commit()

    if not dry_run and rotated_per_org:
        for org_id, counts in rotated_per_org.items():
            record_audit_event(
                session,
                org_id=org_id,
                actor_operator_id=None,
                action=ROTATION_AUDIT_ACTION,
                target_type="organization",
                target_id=org_id,
                context={"to_key_version": current, "rows": dict(counts), "via": "cli"},
            )
        session.commit()
    return report
