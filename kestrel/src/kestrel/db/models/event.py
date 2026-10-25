# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, enum_column


class ChangeType(str, enum.Enum):
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    UNCHANGED = "unchanged"


class Event(Base, TenantMixin):
    """Change-detection log: a normalized diff between collection runs.

    Written by ``kestrel.sync.pipeline`` by comparing each run's normalized rows
    against live entity state (row-diffing). Immutable hashed graph snapshots
    are also written per successful run (``kestrel.graph.snapshots``)
    as the evidence record that can be diffed pairwise — snapshots do not
    replace row-diff Events during rollout.
    """

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_entity", "org_id", "entity_type", "entity_id", "detected_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    change_type: Mapped[ChangeType] = mapped_column(enum_column(ChangeType, name="change_type"), nullable=False)
    field_changes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
