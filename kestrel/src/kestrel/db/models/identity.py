# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin, enum_column


class IdentityType(str, enum.Enum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    EXTERNAL_IDENTITY = "external_identity"


class EmploymentStatus(str, enum.Enum):
    ACTIVE = "active"
    TERMINATED = "terminated"


class WorkerType(str, enum.Enum):
    """How the organization relates to the person behind an account.

    Stored as a plain string column rather than a Postgres enum so a new value
    needs no ``ALTER TYPE`` migration. ``unknown`` is a real value: most
    providers say nothing about employment, and only the identity provider's
    profile or an operator classification rule can turn it into something else.
    """

    EMPLOYEE = "employee"
    CONTRACTOR = "contractor"
    VENDOR_OR_PARTNER = "vendor_or_partner"
    GUEST = "guest"
    SERVICE = "service"
    UNKNOWN = "unknown"


WORKER_TYPES = frozenset(member.value for member in WorkerType)
# A person the organization pays for their time, as opposed to a guest it merely
# lets in or a bot. Policies about "contractors" normally mean both.
CONTINGENT_WORKER_TYPES = frozenset({WorkerType.CONTRACTOR.value, WorkerType.VENDOR_OR_PARTNER.value})


def coerce_worker_type(value: object) -> str:
    """``value`` as a stored worker type; anything unrecognized is ``unknown``."""
    if isinstance(value, WorkerType):
        return value.value
    if isinstance(value, str) and value.strip().lower() in WORKER_TYPES:
        return value.strip().lower()
    return WorkerType.UNKNOWN.value


class Identity(Base, ProvenanceMixin):
    """Base identity row -- polymorphic parent via identity_type, with a 1:1
    detail table (User / ServiceAccount / ExternalIdentity) for type-specific
    attributes."""

    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("application_instance_id", "provider_object_id"),
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_identities_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_identities_org_worker_type", "org_id", "worker_type", postgresql_where=text("deleted_at IS NULL")),
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
    # sign-in field), ``audit`` (derived from an audit-log entry the account
    # produced), ``analytics`` (a provider usage report), ``profile`` (a
    # profile-updated timestamp, which is not activity). Dormancy policies must
    # only trust the first three (``TRUSTED_ACTIVITY_SOURCES`` in
    # ``kestrel.policies.runtime.helpers``); the UI labels the rest.
    last_active_source: Mapped[str | None] = mapped_column(String, nullable=True)
    # Employment relationship, see ``WorkerType``. ``worker_type_source`` says
    # where it came from: ``connector`` (the provider's own profile field) or
    # ``rule:<id>`` (an operator classification rule).
    worker_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=WorkerType.UNKNOWN.value, server_default=WorkerType.UNKNOWN.value
    )
    worker_type_source: Mapped[str | None] = mapped_column(String, nullable=True)
    department: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    manager_email: Mapped[str | None] = mapped_column(String, nullable=True)
    # When the provider disabled the account (Okta ``statusChanged`` on a
    # suspended or deprovisioned user). Null when the provider has no such
    # timestamp even though ``is_disabled`` is true.
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When the account is due to stop working (a Slack guest's expiration).
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Provider-specific extras the normalizer emitted that have no column of
    # their own (org unit path, guest tier, admin flags, raw user type, ...).
    # Policies read them as ``identity.attributes``; the sync keeps the keys
    # sorted and drops nulls so equality is stable across runs.
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))


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
