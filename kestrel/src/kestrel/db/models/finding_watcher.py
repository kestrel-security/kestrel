# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator finding watch subscriptions.

Distinct from assignment and mute/snooze. Watchers
receive in-app inbox rows on finding open/resolve via notification dispatch,
even when org-wide finding prefs would otherwise suppress delivery
(channel mute still applies).
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin


class FindingWatcher(Base, TenantMixin, TimestampMixin):
    """One (operator, finding) watch subscription within an org."""

    __tablename__ = "finding_watchers"
    __table_args__ = (UniqueConstraint("org_id", "operator_id", "finding_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("operators.id"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
