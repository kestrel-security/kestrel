# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared SQLAlchemy declarative base and mixins.

Every normalized source-of-truth object in the Kestrel data model (Identity,
Group, Role, Permission, Resource, OAuthApplication, ...) carries a common set
of provenance fields per the product spec: a stable Kestrel id, the provider's
own id, the owning application instance, the owning tenant, first/last-seen
timestamps, the collection run that produced it, the original raw source
object, and a schema version. ``ProvenanceMixin`` centralizes those fields so
every entity table gets them consistently.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def enum_column[E: enum.Enum](enum_cls: type[E], name: str) -> Enum:
    """SQLAlchemy's Enum type stores a Python enum member's `.name` (e.g.
    "ROLE") in Postgres by default, not its `.value` (e.g. "role") --
    ORM reads translate this back to the right member automatically, but
    raw SQL (e.g. graph/queries.py's recursive CTE) bypasses that
    translation and sees the raw stored name instead. Storing `.value`
    directly keeps every code path consistent."""
    return Enum(enum_cls, name=name, values_callable=lambda x: [e.value for e in x])


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TenantMixin:
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True, nullable=False)


class SoftDeleteMixin:
    """Tombstone for rows the provider stopped reporting.

    ``detect_deletions`` sets ``deleted_at`` instead of removing the row, so
    provenance, evidence, and the Changes feed keep pointing at something. Every
    read path that answers "what exists now" -- policy row loaders, the
    identities API, graph nodes, search, finding reconciliation -- must filter
    with ``is_active(model)``. A row that reappears in a later collection is
    revived (``deleted_at`` cleared) and reported as CREATED again.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def is_active(model: type[SoftDeleteMixin]) -> Any:
    """SQL predicate selecting rows that have not been tombstoned."""
    return model.deleted_at.is_(None)


class ProvenanceMixin(TenantMixin, TimestampMixin, SoftDeleteMixin):
    """Common fields for every normalized entity. Subclasses should also add
    ``__table_args__ = (UniqueConstraint("application_instance_id", "provider_object_id"),)``
    since a mixin cannot declare a per-table unique constraint on its own.
    """

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_instances.id"), index=True, nullable=False
    )
    provider_object_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    source_connector_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=False
    )
    raw_source: Mapped[dict] = mapped_column(JSONB, nullable=False)
    schema_version: Mapped[int] = mapped_column(default=1, nullable=False)
