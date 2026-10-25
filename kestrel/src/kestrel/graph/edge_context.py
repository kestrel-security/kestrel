# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Graph edge explainability: why an access-graph edge exists.

Complements node context. Explanations are derived from
``edge_type``, ``access_path``, endpoint labels, and first-seen connector
run provenance — no stored explanation column.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorRun
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.oauth import OAuthScope
from kestrel.graph.context import detail_path_for_node, graph_focus_path_for_node

_EDGE_TYPE_PHRASE: dict[GraphEdgeType, str] = {
    GraphEdgeType.MEMBER_OF: "is a member of",
    GraphEdgeType.ASSIGNED_ROLE: "is assigned the role",
    GraphEdgeType.GRANTS_PERMISSION: "grants the permission",
    GraphEdgeType.HAS_PERMISSION: "has the permission",
    GraphEdgeType.CAN_ACCESS: "can access",
    GraphEdgeType.APPLIES_TO: "applies to",
    GraphEdgeType.POSSESSES_SCOPE: "possesses the OAuth scope",
    GraphEdgeType.SUPPORTED_BY: "is supported by",
    GraphEdgeType.MAPS_TO: "maps to",
}

_ACCESS_PATH_PHRASE: dict[AccessPath, str] = {
    AccessPath.DIRECT: "via a direct assignment",
    AccessPath.INHERITED_GROUP: "via group membership (inherited)",
    AccessPath.INHERITED_ROLE: "via a role assignment (inherited)",
    AccessPath.OAUTH_DERIVED: "via an OAuth grant",
    AccessPath.FEDERATED: "via federated identity",
}

_NODE_TYPE_ARTICLE: dict[GraphNodeType, str] = {
    GraphNodeType.IDENTITY: "identity",
    GraphNodeType.APPLICATION: "application",
    GraphNodeType.GROUP: "group",
    GraphNodeType.ROLE: "role",
    GraphNodeType.PERMISSION: "permission",
    GraphNodeType.RESOURCE: "resource",
    GraphNodeType.OAUTH_APPLICATION: "OAuth application",
    GraphNodeType.SETTING: "setting",
}


def _detail_path(node: GraphNode) -> str | None:
    return detail_path_for_node(node)


def _graph_focus_path(node: GraphNode) -> str:
    return graph_focus_path_for_node(node)


def _node_summary(node: GraphNode) -> dict:
    return {
        "id": node.id,
        "node_type": node.node_type.value,
        "object_id": node.object_id,
        "label": node.label,
        "properties": node.properties or {},
    }


def oauth_scopes_by_app(
    db: Session, *, org_id: uuid.UUID, oauth_app_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    """Load scopes for OAuth apps. Does not materialize scope nodes."""
    if not oauth_app_ids:
        return {}
    rows = db.scalars(
        select(OAuthScope)
        .where(
            OAuthScope.org_id == org_id,
            OAuthScope.oauth_application_id.in_(oauth_app_ids),
        )
        .order_by(OAuthScope.scope_name)
    ).all()
    out: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for scope in rows:
        out[scope.oauth_application_id].append(
            {
                "name": scope.scope_name,
                "is_sensitive": bool(scope.is_sensitive),
            }
        )
    return out


def explain_edge(edge: GraphEdge, source: GraphNode, target: GraphNode) -> str:
    """Plain-language sentence for operators inspecting a graph edge.

    Includes ``permission_level`` / ``membership_role`` from edge properties
    when present.
    """
    verb = _EDGE_TYPE_PHRASE.get(edge.edge_type, f"has a {edge.edge_type.value} relationship to")
    source_kind = _NODE_TYPE_ARTICLE.get(source.node_type, source.node_type.value)
    target_kind = _NODE_TYPE_ARTICLE.get(target.node_type, target.node_type.value)
    props = edge.properties or {}
    detail = ""
    permission = props.get("permission_level")
    if isinstance(permission, str) and permission.strip():
        detail = f" with {permission.strip()} permission"
    membership = props.get("membership_role")
    if isinstance(membership, str) and membership.strip() and not detail:
        detail = f" as {membership.strip()}"
    path = ""
    if edge.access_path is not None:
        path = f" {_ACCESS_PATH_PHRASE.get(edge.access_path, f'via {edge.access_path.value}')}"
    return f"The {source_kind} “{source.label}” {verb} the {target_kind} “{target.label}”{detail}{path}."


def _provenance(db: Session, edge: GraphEdge) -> dict | None:
    if edge.source_connector_run_id is None:
        return None
    run = db.get(ConnectorRun, edge.source_connector_run_id)
    if run is None or run.org_id != edge.org_id:
        return {
            "connector_run_id": edge.source_connector_run_id,
            "connector_instance_id": None,
            "status": None,
            "triggered_by": None,
            "started_at": None,
            "finished_at": None,
        }
    return {
        "connector_run_id": run.id,
        "connector_instance_id": run.connector_instance_id,
        "status": run.status.value,
        "triggered_by": run.triggered_by.value,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


def graph_edge_context(db: Session, edge: GraphEdge, source: GraphNode, target: GraphNode) -> dict:
    """Payload for GET /graph/edges/{id}."""
    props: dict[str, Any] = dict(edge.properties or {})
    if edge.edge_type == GraphEdgeType.POSSESSES_SCOPE:
        oauth_node = (
            target
            if target.node_type == GraphNodeType.OAUTH_APPLICATION
            else source
            if source.node_type == GraphNodeType.OAUTH_APPLICATION
            else None
        )
        if oauth_node is not None:
            scopes_map = oauth_scopes_by_app(db, org_id=edge.org_id, oauth_app_ids=[oauth_node.object_id])
            scopes = scopes_map.get(oauth_node.object_id)
            if scopes:
                props["scopes"] = scopes

    return {
        "edge": {
            "id": edge.id,
            "edge_type": edge.edge_type.value,
            "access_path": edge.access_path.value if edge.access_path else None,
            "first_seen_at": edge.first_seen_at.isoformat() if edge.first_seen_at else None,
            "last_seen_at": edge.last_seen_at.isoformat() if edge.last_seen_at else None,
            "properties": props,
            "source_node_id": edge.source_node_id,
            "target_node_id": edge.target_node_id,
        },
        "source": _node_summary(source),
        "target": _node_summary(target),
        "provenance": _provenance(db, edge),
        "explanation": explain_edge(edge, source, target),
        "entity": {
            "source_detail_path": _detail_path(source),
            "target_detail_path": _detail_path(target),
            "source_graph_focus_path": _graph_focus_path(source),
            "target_graph_focus_path": _graph_focus_path(target),
        },
    }
