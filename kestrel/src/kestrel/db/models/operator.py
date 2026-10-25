# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator: a person who logs into Kestrel itself (email/password or, later,
SSO), distinct from `Identity` (a person discovered *within* a connected
SaaS app by a connector). Named `Operator` specifically to avoid colliding
with `User`/`Role`/`Permission`/`Group`/`Grant`, which already model
discovered SaaS access data in the graph.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class OperatorRole(str, enum.Enum):
    READ_ONLY = "read_only"
    ANALYST = "analyst"
    ADMIN = "admin"


class Operator(Base, TenantMixin, TimestampMixin):
    """A Kestrel login account. Composes TenantMixin + TimestampMixin directly
    (not ProvenanceMixin -- no connector-provenance fields apply to a login
    account)."""

    __tablename__ = "operators"
    __table_args__ = (UniqueConstraint("org_id", "email"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, index=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    # Nullable: a future SSO-only operator has no local password.
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[OperatorRole] = mapped_column(enum_column(OperatorRole, name="operator_role"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Operator-scoped UI prefs (dashboard layout; extensible JSON).
    ui_preferences: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # TOTP second factor (kestrel.auth.mfa). The secret is AES-GCM encrypted
    # with the org key; it may exist before `mfa_enabled_at` while enrolment
    # is pending, and only counts once the first code has been verified.
    mfa_secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_secret_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_secret_key_version: Mapped[int | None] = mapped_column(nullable=True)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The last TOTP time step accepted, so a code cannot be replayed.
    mfa_last_used_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class OperatorSession(Base):
    """A browser-driven login session. Sliding expiry (`expires_at`, pushed
    forward on each use) capped by a fixed `absolute_expires_at` that never
    extends."""

    __tablename__ = "operator_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # MFA_STATE_*: a "challenge" session only proves the password and may only
    # finish sign-in; an "enroll" session may only set up MFA.
    mfa_state: Mapped[str] = mapped_column(String(16), nullable=False, default="verified", server_default="verified")
    mfa_failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")


MFA_STATE_VERIFIED = "verified"
MFA_STATE_CHALLENGE = "challenge"
MFA_STATE_ENROLL = "enroll"


class OperatorMfaRecoveryCode(Base):
    """A single-use recovery code for an operator's second factor, stored hashed."""

    __tablename__ = "operator_mfa_recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiToken(Base, TenantMixin, TimestampMixin):
    """A long-lived CLI/automation credential, independent of any browser
    session."""

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    # Short, non-secret prefix (e.g. "kvr_ab12cd34") so the UI can show
    # "which token is this" without ever re-displaying the secret.
    token_prefix: Mapped[str] = mapped_column(String, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
