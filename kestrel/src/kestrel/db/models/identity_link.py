# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Persisted cross-application identity correlation.

Correlation itself is a read-time union-find over every identity in the org
(:mod:`kestrel.identities.correlate`). Recomputing it on every Explore search,
identity read, and cross-app policy evaluation is the single most expensive
repeated query in the product: it loads the whole directory to answer a
question about one person.

This table is that computation, materialized once per sync. One row per
identity, naming the cluster it belongs to and how it was matched, so a
lookup is an indexed read. It is a derived read model like the graph: safe to
delete, rebuilt by ``rebuild_identity_links``.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin


class IdentityLink(Base, TenantMixin):
    __tablename__ = "identity_links"
    __table_args__ = (
        UniqueConstraint("org_id", "identity_id"),
        Index("ix_identity_links_cluster", "org_id", "cluster_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The cluster's representative identity id, as text. Stable while the
    # cluster's membership is stable; recomputed wholesale on every rebuild.
    cluster_key: Mapped[str] = mapped_column(String, nullable=False)
    representative_identity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # How this account joined the cluster: "email" (high confidence),
    # "display_name" (medium), or "self" (a single-account cluster).
    match_kind: Mapped[str] = mapped_column(String, nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    application_types: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
