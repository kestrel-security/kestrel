# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Daily posture trend snapshots.

One row per org per UTC calendar day. Captured forward-only — never backfilled.
"""

import uuid
from datetime import date

from sqlalchemy import Date, Integer, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin


class PostureTrendSnapshot(Base, TenantMixin, TimestampMixin):
    __tablename__ = "posture_trend_snapshots"
    __table_args__ = (UniqueConstraint("org_id", "snapshot_date", name="uq_posture_trend_org_date"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    # {critical, high, medium, low} open finding counts
    open_by_severity: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Scorecard factor keys → counts
    factor_counts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    attention_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
