# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator in-app notification inbox rows.

Delivered when finding lifecycle events fire or an outbound webhook delivery
fails, and the operator's preferences allow ``channel=in_app``. Distinct from org outbound webhooks and from
finding mute.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin


class OperatorInAppNotification(Base, TenantMixin, TimestampMixin):
    """One inbox row per (operator, event) delivery."""

    __tablename__ = "operator_in_app_notifications"
    # The inbox query: one operator's unread-first, newest-first rows (migration c4d5e6f7a8b9).
    __table_args__ = (Index("ix_operator_in_app_notifications_inbox", "org_id", "operator_id", "read_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False, index=True
    )
    # finding | webhook_failure
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # e.g. finding.opened / finding.resolved
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True, index=True
    )
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
