# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator notification preferences.

Distinct from finding mute/snooze and from org-level outbound
webhook endpoints. In-app and email delivery both read these prefs
via ``should_notify``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin


class OperatorNotificationPreferences(Base, TenantMixin, TimestampMixin):
    """One row per operator: channel mutes + finding severity threshold."""

    __tablename__ = "operator_notification_preferences"
    __table_args__ = (UniqueConstraint("org_id", "operator_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False, index=True
    )
    email_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    in_app_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    findings_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    webhook_failures_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Notify for findings at or above this severity (low|medium|high|critical).
    min_severity: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    # Event types the operator has muted (subset of finding.opened / finding.resolved).
    muted_events: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
