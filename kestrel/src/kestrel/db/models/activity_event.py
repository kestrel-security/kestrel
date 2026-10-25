# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Provider audit / activity events.

Distinct from change-detection ``events`` (sync diffs). These are normalized
SaaS audit-log rows (privileged grants, MFA changes, OAuth consents, …)
collected by connectors and evaluated by the legacy policy DSL ``from events`` policies.
"""

from datetime import datetime

from sqlalchemy import DateTime, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, ProvenanceMixin


class ActivityEvent(Base, ProvenanceMixin):
    __tablename__ = "activity_events"
    __table_args__ = (
        UniqueConstraint("application_instance_id", "provider_object_id"),
        Index("ix_activity_events_org_occurred", "org_id", "occurred_at"),
        Index("ix_activity_events_org_action", "org_id", "action"),
    )

    # Normalized action key used by policies (e.g. privilege.grant).
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    action_category: Mapped[str] = mapped_column(String, nullable=False, index=True)
    actor_email: Mapped[str | None] = mapped_column(String, nullable=True)
    actor_provider_id: Mapped[str | None] = mapped_column(String, nullable=True)
    target_email: Mapped[str | None] = mapped_column(String, nullable=True)
    target_type: Mapped[str | None] = mapped_column(String, nullable=True)
    target_provider_id: Mapped[str | None] = mapped_column(String, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
