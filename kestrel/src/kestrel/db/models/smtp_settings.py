# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-scoped outbound mail server (SMTP) settings.

The optional password is envelope-encrypted like other integration secrets
(ADR-0004) and accepted only on write -- never returned again. Without a row,
email falls back to the deployment-wide ``KESTREL_SMTP_*`` environment.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin

SECURITY_STARTTLS = "starttls"
SECURITY_SSL = "ssl"
SECURITY_NONE = "none"
SMTP_SECURITY_MODES = frozenset({SECURITY_STARTTLS, SECURITY_SSL, SECURITY_NONE})

DEFAULT_PORTS = {SECURITY_STARTTLS: 587, SECURITY_SSL: 465, SECURITY_NONE: 25}


class OrgSmtpSettings(Base, TenantMixin, TimestampMixin):
    """One optional mail server config row per organization."""

    __tablename__ = "org_smtp_settings"
    __table_args__ = (UniqueConstraint("org_id", name="uq_org_smtp_settings_org_id"),)

    # Per-org settings go with the organization (the migration declared the cascade).
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host: Mapped[str] = mapped_column(Text, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    security: Mapped[str] = mapped_column(String(16), nullable=False, default=SECURITY_STARTTLS)
    username: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_key_version: Mapped[int | None] = mapped_column(nullable=True)
    from_address: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
