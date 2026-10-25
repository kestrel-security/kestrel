# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TenantMixin, TimestampMixin, enum_column


class GraphNodeType(str, enum.Enum):
    IDENTITY = "identity"
    APPLICATION = "application"
    GROUP = "group"
    ROLE = "role"
    PERMISSION = "permission"
    RESOURCE = "resource"
    OAUTH_APPLICATION = "oauth_application"
    SETTING = "setting"


class GraphEdgeType(str, enum.Enum):
    MEMBER_OF = "member_of"
    ASSIGNED_ROLE = "assigned_role"
    GRANTS_PERMISSION = "grants_permission"
    HAS_PERMISSION = "has_permission"
    CAN_ACCESS = "can_access"
    APPLIES_TO = "applies_to"
    POSSESSES_SCOPE = "possesses_scope"
    SUPPORTED_BY = "supported_by"
    MAPS_TO = "maps_to"


class AccessPath(str, enum.Enum):
    DIRECT = "direct"
    INHERITED_GROUP = "inherited_group"
    INHERITED_ROLE = "inherited_role"
    OAUTH_DERIVED = "oauth_derived"
    FEDERATED = "federated"


class GraphNode(Base, TenantMixin, TimestampMixin):
    """Derived read-model: one row per graph-participating entity. Rebuilt
    (upserted) from the normalized entity tables by graph/writer.py during
    normalization -- entity tables remain the source of truth (see ADR-0003).
    """

    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("org_id", "node_type", "object_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    node_type: Mapped[GraphNodeType] = mapped_column(enum_column(GraphNodeType, name="graph_node_type"), nullable=False)
    object_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    properties: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class GraphEdge(Base, TenantMixin):
    __tablename__ = "graph_edges"
    __table_args__ = (
        Index("ix_graph_edges_source", "org_id", "source_node_id", "edge_type"),
        Index("ix_graph_edges_target", "org_id", "target_node_id", "edge_type"),
        UniqueConstraint(
            "org_id",
            "source_node_id",
            "target_node_id",
            "edge_type",
            "access_path",
            name="uq_graph_edges_endpoints",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id"), nullable=False)
    target_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id"), nullable=False)
    edge_type: Mapped[GraphEdgeType] = mapped_column(enum_column(GraphEdgeType, name="graph_edge_type"), nullable=False)
    access_path: Mapped[AccessPath | None] = mapped_column(enum_column(AccessPath, name="access_path"), nullable=True)
    source_connector_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    properties: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
