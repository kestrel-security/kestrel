# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Cross-application privileged role lookups for identity risk factors.

Privileged roles per identity, correlated by email (same semantics as pack policy
``cross-app-privileged-concentration``). Uses the graph privilege definition
(``assigned_role`` → ``Role.is_privileged``), not the grants table.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from kestrel.db.models.access import Role
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity


def _email_key(email: str | None) -> str | None:
    if email is None:
        return None
    key = email.strip().lower()
    return key or None


def _privileged_role_rows(db: Session, org_id: uuid.UUID) -> list[Any]:
    """One row per (identity, privileged role) via assigned_role edges."""
    identity_node = aliased(GraphNode)
    role_node = aliased(GraphNode)
    return list(
        db.execute(
            select(
                Identity.id.label("identity_id"),
                Identity.email,
                Identity.display_name,
                Identity.application_instance_id,
                ApplicationInstance.display_name.label("application_display_name"),
                Application.application_type,
                Role.name.label("role_name"),
                Role.id.label("role_id"),
            )
            .select_from(Identity)
            .join(identity_node, identity_node.object_id == Identity.id)
            .join(GraphEdge, GraphEdge.source_node_id == identity_node.id)
            .join(role_node, role_node.id == GraphEdge.target_node_id)
            .join(Role, Role.id == role_node.object_id)
            .join(ApplicationInstance, ApplicationInstance.id == Identity.application_instance_id)
            .join(Application, Application.id == ApplicationInstance.application_id)
            .where(
                Identity.org_id == org_id,
                Identity.email.is_not(None),
                func.length(func.trim(Identity.email)) > 0,
                identity_node.org_id == org_id,
                identity_node.node_type == GraphNodeType.IDENTITY,
                GraphEdge.org_id == org_id,
                GraphEdge.edge_type == GraphEdgeType.ASSIGNED_ROLE,
                role_node.node_type == GraphNodeType.ROLE,
                Role.is_privileged.is_(True),
                ApplicationInstance.org_id == org_id,
            )
            .order_by(Identity.email, Application.application_type, Role.name)
        ).all()
    )
