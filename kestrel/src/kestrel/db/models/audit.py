# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Real, user-attributed audit logging. Consumed well beyond login (finding
changes, sync triggers, operator management), so this lives as its own
model, not folded into operator.py."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin


class AuditLog(Base, TenantMixin):
    """Immutable append-only rows -- no TimestampMixin (no updated_at)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_org_created", "org_id", "created_at"),
        Index("ix_audit_log_target", "target_type", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable: some actions (e.g. an auth.login_failed for an unknown email)
    # have no resolvable actor.
    actor_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=True
    )
    # Free-text, dotted namespace (e.g. "auth.login_succeeded",
    # "finding.status_changed") -- not a rigid enum, the taxonomy will grow.
    action: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String, nullable=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    # Python attribute `context`, DB column `metadata` -- `metadata` is a
    # reserved name on SQLAlchemy's declarative Base.
    context: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
