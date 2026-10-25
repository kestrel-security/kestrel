# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin, SoftDeleteMixin, TenantMixin, enum_column


class GrantedVia(str, enum.Enum):
    DIRECT = "direct"
    GROUP = "group"
    ROLE_ASSIGNMENT = "role_assignment"


class Group(Base, ProvenanceMixin):
    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("application_instance_id", "provider_object_id"),)

    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)


class GroupMembership(Base, TenantMixin, SoftDeleteMixin):
    __tablename__ = "group_memberships"
    __table_args__ = (
        UniqueConstraint("group_id", "identity_id"),
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_group_memberships_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), nullable=False, index=True)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=False, index=True
    )
    source_connector_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Role(Base, ProvenanceMixin):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("application_instance_id", "provider_object_id"),)

    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Permission(Base, ProvenanceMixin):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("application_instance_id", "provider_object_id"),)

    name: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("permissions.id"), primary_key=True)


class Grant(Base, TenantMixin, SoftDeleteMixin):
    """Central access-relationship table: Identity -> Permission and/or Role,
    direct or via a group, optionally scoped to a specific resource. Backs the
    "direct privilege grant bypassing group-based access" and "newly created
    admin grant" policies directly.

    identity_id is nullable because a grant can be scoped above the identity
    level -- e.g. "this team grants admin on this repo" (source_group_id +
    resource_id set, identity_id null). Per-member access for that case is
    derived by traversing the graph (identity -MEMBER_OF-> group -CAN_ACCESS->
    resource) rather than materialized as one Grant row per member, to avoid
    a combinatorial blow-up as teams/repos grow."""

    __tablename__ = "grants"
    # The sync upsert's lookup key. Most of it is nullable, hence NULLS NOT
    # DISTINCT: two org-wide team grants with no identity are still the same row.
    __table_args__ = (
        Index(
            "uq_grants_natural_key",
            "org_id",
            "identity_id",
            "resource_id",
            "role_id",
            "source_group_id",
            "granted_via",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
        # Partial index for the common "live rows of this org" scans (migration e3f4a5b6c7d8).
        Index("ix_grants_active_org", "org_id", postgresql_where=text("deleted_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=True, index=True
    )
    permission_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=True)
    role_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=True, index=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resources.id"), nullable=True, index=True
    )
    granted_via: Mapped[GrantedVia] = mapped_column(enum_column(GrantedVia, name="granted_via"), nullable=False)
    # Coarse permission level (e.g. "read"/"write"/"admin") for resource-scoped
    # grants that don't warrant a full Role row of their own -- GitHub repo
    # collaborator/team permissions are the canonical example. Distinct from
    # role_id, which is reserved for globally meaningful roles (e.g. GitHub's
    # organization_admin) that also participate in the graph as their own node.
    permission_level: Mapped[str | None] = mapped_column(String, nullable=True)
    source_group_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), nullable=True)
    source_connector_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
