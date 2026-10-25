# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin, enum_column


class IdentityType(str, enum.Enum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    EXTERNAL_IDENTITY = "external_identity"


class EmploymentStatus(str, enum.Enum):
    ACTIVE = "active"
    TERMINATED = "terminated"


class Identity(Base, ProvenanceMixin):
    """Base identity row -- polymorphic parent via identity_type, with a 1:1
    detail table (User / ServiceAccount / ExternalIdentity) for type-specific
    attributes."""

    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("application_instance_id", "provider_object_id"),
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_identities_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
    )

    identity_type: Mapped[IdentityType] = mapped_column(enum_column(IdentityType, name="identity_type"), nullable=False)
    email: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_external: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Where ``last_active_at`` came from: ``login`` (the provider's own last
    # sign-in field), ``audit`` (derived from an audit-log sign-in event),
    # ``profile`` (a profile-updated timestamp, which is not activity). Dormancy
    # policies must only trust ``login`` and ``audit``; the UI labels the rest.
    last_active_source: Mapped[str | None] = mapped_column(String, nullable=True)


class User(Base):
    """1:1 detail table for identities where identity_type == user."""

    __tablename__ = "users"

    identity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id"), primary_key=True)
    employment_status: Mapped[EmploymentStatus | None] = mapped_column(
        enum_column(EmploymentStatus, name="employment_status"), nullable=True
    )


class ServiceAccount(Base):
    """1:1 detail table for identities where identity_type == service_account.
    A null owner_identity_id is the signal for "service account without a
    known owner"."""

    __tablename__ = "service_accounts"

    identity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id"), primary_key=True)
    owner_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=True
    )


class ExternalIdentity(Base):
    """1:1 detail table for identities where identity_type == external_identity."""

    __tablename__ = "external_identities"

    identity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id"), primary_key=True)
    source_domain: Mapped[str | None] = mapped_column(String, nullable=True)
