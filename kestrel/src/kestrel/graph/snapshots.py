# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Hashed graph snapshots per successful sync run.

Snapshots run *alongside* row-diff change detection as an immutable evidence
record of what the graph looked like after each sync. Retention defaults to keeping the last
N snapshots per application instance.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func, select
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, Session, mapped_column

from kestrel.db.base import Base, TenantMixin
from kestrel.db.models.graph_edge import GraphEdge, GraphNode

DEFAULT_RETENTION = 30


class GraphSnapshot(Base, TenantMixin):
    """Immutable content-hashed snapshot of graph nodes/edges after a sync."""

    __tablename__ = "graph_snapshots"
    __table_args__ = (
        Index(
            "ix_graph_snapshots_instance_created",
            "org_id",
            "application_instance_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("application_instances.id"), nullable=False
    )
    connector_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_runs.id"), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def content_hash_payload(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _payload_for_nodes(session: Session, *, org_id: uuid.UUID, node_ids: set[uuid.UUID]) -> dict[str, Any]:
    if not node_ids:
        return {"nodes": [], "edges": []}
    nodes = session.scalars(select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.id.in_(node_ids))).all()
    edges = session.scalars(
        select(GraphEdge).where(
            GraphEdge.org_id == org_id,
            GraphEdge.source_node_id.in_(node_ids),
            GraphEdge.target_node_id.in_(node_ids),
        )
    ).all()
    node_rows = sorted(
        [
            {
                "id": str(n.id),
                "node_type": n.node_type.value if hasattr(n.node_type, "value") else str(n.node_type),
                "object_id": str(n.object_id),
                "label": n.label,
            }
            for n in nodes
        ],
        key=lambda r: (r["node_type"], r["object_id"], r["id"]),
    )
    edge_rows = sorted(
        [
            {
                "id": str(e.id),
                "edge_type": e.edge_type.value if hasattr(e.edge_type, "value") else str(e.edge_type),
                "source_node_id": str(e.source_node_id),
                "target_node_id": str(e.target_node_id),
                "access_path": (
                    e.access_path.value
                    if e.access_path is not None and hasattr(e.access_path, "value")
                    else (str(e.access_path) if e.access_path is not None else None)
                ),
            }
            for e in edges
        ],
        key=lambda r: (r["edge_type"], r["source_node_id"], r["target_node_id"], r["id"]),
    )
    return {"nodes": node_rows, "edges": edge_rows}


def write_graph_snapshot(
    session: Session,
    *,
    org_id: uuid.UUID,
    application_instance_id: uuid.UUID,
    connector_run_id: uuid.UUID,
    node_id_maps: dict[str, dict[str, uuid.UUID]] | None = None,
    retention: int = DEFAULT_RETENTION,
) -> GraphSnapshot:
    node_ids: set[uuid.UUID] = set()
    if node_id_maps:
        for by_provider in node_id_maps.values():
            node_ids.update(by_provider.values())
    payload = _payload_for_nodes(session, org_id=org_id, node_ids=node_ids)
    digest = content_hash_payload(payload)
    snap = GraphSnapshot(
        id=uuid.uuid4(),
        org_id=org_id,
        application_instance_id=application_instance_id,
        connector_run_id=connector_run_id,
        content_hash=digest,
        node_count=len(payload["nodes"]),
        edge_count=len(payload["edges"]),
        payload=payload,
        created_at=datetime.now(UTC),
    )
    session.add(snap)
    session.flush()

    older = session.scalars(
        select(GraphSnapshot)
        .where(
            GraphSnapshot.org_id == org_id,
            GraphSnapshot.application_instance_id == application_instance_id,
        )
        .order_by(GraphSnapshot.created_at.desc())
        .offset(max(retention, 1))
    ).all()
    for row in older:
        session.delete(row)
    session.flush()
    return snap
