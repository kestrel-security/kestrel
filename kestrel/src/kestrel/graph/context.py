# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Graph node investigation context: resolve entity links, open findings,
and immediate neighbor counts for the Access Graph workbench panel."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.graph_edge import GraphEdge, GraphNode, GraphNodeType

OPEN_FINDINGS_LIMIT = 8

# Graph node types that can be finding subjects.
_SUBJECT_NODE_TYPES = frozenset(
    {
        GraphNodeType.IDENTITY,
        GraphNodeType.RESOURCE,
        GraphNodeType.OAUTH_APPLICATION,
    }
)


def detail_path_for_node(node: GraphNode) -> str | None:
    if node.node_type == GraphNodeType.IDENTITY:
        # Full identity hub was removed from nav; Explore + Findings remain.
        return f"/explore?focus={node.object_id}&focus_type=identity&direction=out"
    if node.node_type == GraphNodeType.GROUP:
        return f"/explore?focus={node.object_id}&focus_type=group&direction=both"
    if node.node_type == GraphNodeType.RESOURCE:
        return f"/explore?focus={node.object_id}&focus_type=resource&direction=in"
    if node.node_type == GraphNodeType.OAUTH_APPLICATION:
        return f"/explore?focus={node.object_id}&focus_type=oauth_application&direction=in"
    if node.node_type == GraphNodeType.APPLICATION:
        return "/connectors"
    return None


def graph_focus_path_for_node(node: GraphNode) -> str:
    """URL to refocus Explore on this entity."""
    if node.node_type == GraphNodeType.GROUP:
        direction = "both"
    elif node.node_type in {
        GraphNodeType.RESOURCE,
        GraphNodeType.OAUTH_APPLICATION,
        GraphNodeType.PERMISSION,
        GraphNodeType.SETTING,
    }:
        direction = "in"
    else:
        direction = "out"
    return f"/explore?focus={node.object_id}&focus_type={node.node_type.value}&direction={direction}"


def _detail_path(node: GraphNode) -> str | None:
    return detail_path_for_node(node)


def _graph_focus_path(node: GraphNode) -> str:
    return graph_focus_path_for_node(node)


def _findings_list_path(node: GraphNode) -> str | None:
    if node.node_type not in _SUBJECT_NODE_TYPES:
        return None
    return f"/findings?subject_type={node.node_type.value}&subject_id={node.object_id}"


def neighbor_edge_counts(db: Session, *, org_id: uuid.UUID, node_id: uuid.UUID) -> dict[str, int]:
    """Immediate edge counts (not multi-hop) incident to the node."""
    outgoing = (
        db.scalar(
            select(func.count())
            .select_from(GraphEdge)
            .where(GraphEdge.org_id == org_id, GraphEdge.source_node_id == node_id)
        )
        or 0
    )
    incoming = (
        db.scalar(
            select(func.count())
            .select_from(GraphEdge)
            .where(GraphEdge.org_id == org_id, GraphEdge.target_node_id == node_id)
        )
        or 0
    )
    return {
        "outgoing": int(outgoing),
        "incoming": int(incoming),
        "total": int(outgoing) + int(incoming),
    }


def _open_finding_count(db: Session, node: GraphNode) -> int:
    if node.node_type not in _SUBJECT_NODE_TYPES:
        return 0
    subject_type = FindingSubjectType(node.node_type.value)
    return int(
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.org_id == node.org_id,
                Finding.subject_type == subject_type,
                Finding.subject_id == node.object_id,
                Finding.status == FindingStatus.OPEN,
            )
        )
        or 0
    )


def open_findings_for_node(db: Session, node: GraphNode, *, limit: int = OPEN_FINDINGS_LIMIT) -> list[dict]:
    if node.node_type not in _SUBJECT_NODE_TYPES:
        return []
    subject_type = FindingSubjectType(node.node_type.value)
    cap = max(0, min(limit, OPEN_FINDINGS_LIMIT))
    rows = db.scalars(
        select(Finding)
        .where(
            Finding.org_id == node.org_id,
            Finding.subject_type == subject_type,
            Finding.subject_id == node.object_id,
            Finding.status == FindingStatus.OPEN,
        )
        .order_by(Finding.last_seen_at.desc(), Finding.id.desc())
        .limit(cap)
    ).all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "last_seen_at": f.last_seen_at.isoformat(),
        }
        for f in rows
    ]


def graph_node_context(db: Session, node: GraphNode) -> dict:
    """Payload for GET /graph/nodes/{id}/context."""
    from kestrel.identities.correlate import cluster_identity_ids, identity_cluster_for

    open_findings = open_findings_for_node(db, node)
    accounts = None
    neighbor_counts = neighbor_edge_counts(db, org_id=node.org_id, node_id=node.id)
    finding_count = _open_finding_count(db, node)
    node_props = dict(node.properties or {})

    if node.node_type == GraphNodeType.IDENTITY:
        cluster = identity_cluster_for(db, org_id=node.org_id, identity_id=node.object_id)
        if cluster is not None:
            accounts = cluster["accounts"]
            node_props["cluster_size"] = cluster["member_count"]
            node_props["application_types"] = cluster["application_types"]
            # Union neighbor counts + open findings across correlated accounts.
            sibling_ids = cluster_identity_ids(db, org_id=node.org_id, identity_id=node.object_id)
            sibling_nodes = list(
                db.scalars(
                    select(GraphNode).where(
                        GraphNode.org_id == node.org_id,
                        GraphNode.node_type == GraphNodeType.IDENTITY,
                        GraphNode.object_id.in_(sibling_ids),
                    )
                ).all()
            )
            out_total = in_total = 0
            findings_acc: list[dict] = []
            seen_finding_ids: set[uuid.UUID] = set()
            for sib in sibling_nodes:
                counts = neighbor_edge_counts(db, org_id=node.org_id, node_id=sib.id)
                out_total += counts["outgoing"]
                in_total += counts["incoming"]
                for f in open_findings_for_node(db, sib):
                    fid = f["id"] if isinstance(f["id"], uuid.UUID) else uuid.UUID(str(f["id"]))
                    if fid in seen_finding_ids:
                        continue
                    seen_finding_ids.add(fid)
                    findings_acc.append(f)
            neighbor_counts = {
                "outgoing": out_total,
                "incoming": in_total,
                "total": out_total + in_total,
            }
            open_findings = findings_acc[:OPEN_FINDINGS_LIMIT]
            finding_count = len(seen_finding_ids)

    return {
        "node": {
            "id": node.id,
            "node_type": node.node_type.value,
            "object_id": node.object_id,
            "label": node.label,
            "properties": node_props,
        },
        "entity": {
            "detail_path": _detail_path(node),
            "graph_focus_path": _graph_focus_path(node),
            "findings_list_path": _findings_list_path(node),
        },
        "neighbor_counts": neighbor_counts,
        "open_findings": open_findings,
        "open_finding_count": finding_count,
        "accounts": accounts,
    }
