# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin, SoftDeleteMixin, TenantMixin


class OAuthApplication(Base, ProvenanceMixin):
    __tablename__ = "oauth_applications"
    __table_args__ = (UniqueConstraint("application_instance_id", "provider_object_id"),)

    name: Mapped[str] = mapped_column(String, nullable=False)
    publisher: Mapped[str | None] = mapped_column(String, nullable=True)
    is_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    owner_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=True
    )


class OAuthScope(Base, TenantMixin):
    """Scope sensitivity is seeded from a small static ruleset per provider
    (e.g. GitHub's `repo`, `admin:org`) and backs "excessive OAuth scopes"."""

    __tablename__ = "oauth_scopes"
    __table_args__ = (UniqueConstraint("oauth_application_id", "scope_name"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    oauth_application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("oauth_applications.id"), nullable=False, index=True
    )
    scope_name: Mapped[str] = mapped_column(String, nullable=False)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class OAuthGrant(Base, TenantMixin, SoftDeleteMixin):
    """Backs "unused OAuth application with active credentials" via
    last_used_at.

    ``granted_at`` is the provider's own timestamp for the consent; ``first_seen_at``
    is when Kestrel first observed it. They differ whenever a grant predates the
    connector, so change detection keys off first/last_seen_at rather than
    granted_at.
    """

    __tablename__ = "oauth_grants"
    __table_args__ = (
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_oauth_grants_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
        # Revocation detection scans an org's grants by last_seen_at (migration u2v3w4x5y6z7).
        Index("ix_oauth_grants_last_seen_at", "org_id", "last_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    oauth_application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("oauth_applications.id"), nullable=False, index=True
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=False, index=True
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Nullable: rows written before revocation detection existed have no run to
    # attribute them to, and are skipped by detect_deletions until re-synced.
    source_connector_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
