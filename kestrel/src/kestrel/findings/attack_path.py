# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Attack-path narrative over existing graph edges.

Resolves a finding's subject to a graph node, then walks **only** real
``graph_edges`` to produce an ordered hop list with edge explainability
(reuses ``kestrel.graph.edge_context.explain_edge``). Never invents edges
or nodes.

**Algorithm (documented choice):** privilege-relevant BFS — shortest path
from the subject to the highest-scoring privilege sink within
``max_depth``. Among equal lengths, prefer privilege-conveying edge types
(``assigned_role``, ``member_of``, ``possesses_scope``, …) and sinks that
are privileged roles, OAuth applications, resources, or permissions. If
no such path exists (missing node, no outbound edges, or no sink in
range), return empty ``hops`` and an honest ``summary``.
"""

from __future__ import annotations

import uuid
from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.access import Role
from kestrel.db.models.finding import Finding
from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.graph.edge_context import explain_edge

ATTACK_PATH_DEPTH_DEFAULT = 4
ATTACK_PATH_DEPTH_MAX = 6
ATTACK_PATH_ALGORITHM = "privilege_relevant_bfs"

# Edge types that convey privilege / access when ranking equal-length paths.
_PRIVILEGE_EDGE_SCORE: dict[GraphEdgeType, int] = {
    GraphEdgeType.ASSIGNED_ROLE: 100,
    GraphEdgeType.MEMBER_OF: 80,
    GraphEdgeType.POSSESSES_SCOPE: 90,
    GraphEdgeType.GRANTS_PERMISSION: 70,
    GraphEdgeType.HAS_PERMISSION: 70,
    GraphEdgeType.CAN_ACCESS: 60,
    GraphEdgeType.APPLIES_TO: 40,
    GraphEdgeType.SUPPORTED_BY: 20,
    GraphEdgeType.MAPS_TO: 10,
}


def _subject_graph_node(db: Session, finding: Finding) -> GraphNode | None:
    """Resolve finding subject → graph node (org-scoped). Shared logic with
    investigation blast-radius; kept here to avoid circular imports."""
    try:
        node_type = GraphNodeType(finding.subject_type.value)
    except ValueError:
        return None
    return db.scalars(
        select(GraphNode).where(
            GraphNode.org_id == finding.org_id,
            GraphNode.node_type == node_type,
            GraphNode.object_id == finding.subject_id,
        )
    ).first()


def _node_summary(node: GraphNode) -> dict[str, Any]:
    return {
        "id": node.id,
        "node_type": node.node_type.value,
        "object_id": node.object_id,
        "label": node.label,
        "properties": node.properties or {},
    }


def _empty_path(
    finding: Finding,
    *,
    subject_node_id: uuid.UUID | None,
    max_depth: int,
    summary: str,
) -> dict[str, Any]:
    return {
        "finding_id": finding.id,
        "subject_node_id": subject_node_id,
        "algorithm": ATTACK_PATH_ALGORITHM,
        "max_depth": max_depth,
        "hop_count": 0,
        "hops": [],
        "summary": summary,
    }


def _sink_score(db: Session, node: GraphNode) -> int:
    """How interesting a terminal node is for an attack-path narrative."""
    if node.node_type == GraphNodeType.ROLE:
        role = db.get(Role, node.object_id)
        if role is not None and role.org_id == node.org_id and role.is_privileged:
            return 100
        return 50
    if node.node_type == GraphNodeType.OAUTH_APPLICATION:
        return 80
    if node.node_type == GraphNodeType.RESOURCE:
        return 40
    if node.node_type == GraphNodeType.PERMISSION:
        return 30
    if node.node_type == GraphNodeType.GROUP:
        return 15
    if node.node_type == GraphNodeType.APPLICATION:
        return 10
    return 0


def _edge_rank(edge: GraphEdge) -> int:
    return _PRIVILEGE_EDGE_SCORE.get(edge.edge_type, 0)


def _path_rank(db: Session, edges: list[GraphEdge], nodes: dict[uuid.UUID, GraphNode]) -> tuple[int, int, int]:
    """Sort key: higher sink score, shorter path, higher cumulative edge rank."""
    if not edges:
        return (0, 0, 0)
    terminal = nodes[edges[-1].target_node_id]
    sink = _sink_score(db, terminal)
    edge_sum = sum(_edge_rank(e) for e in edges)
    # Prefer shorter: negate length for max-style comparison elsewhere.
    return (sink, -len(edges), edge_sum)


def _outgoing_edges(db: Session, org_id: uuid.UUID, source_node_id: uuid.UUID) -> list[GraphEdge]:
    return list(
        db.scalars(
            select(GraphEdge).where(
                GraphEdge.org_id == org_id,
                GraphEdge.source_node_id == source_node_id,
            )
        ).all()
    )


def _load_nodes(db: Session, org_id: uuid.UUID, node_ids: set[uuid.UUID]) -> dict[uuid.UUID, GraphNode]:
    if not node_ids:
        return {}
    rows = db.scalars(select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.id.in_(node_ids))).all()
    return {n.id: n for n in rows}


def _build_hops(
    db: Session,
    edges: list[GraphEdge],
    nodes: dict[uuid.UUID, GraphNode],
) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for order, edge in enumerate(edges, start=1):
        source = nodes.get(edge.source_node_id)
        target = nodes.get(edge.target_node_id)
        if source is None or target is None:
            # Incomplete inventory — refuse to fabricate; stop path here.
            break
        hops.append(
            {
                "order": order,
                "edge_id": edge.id,
                "edge_type": edge.edge_type.value,
                "access_path": edge.access_path.value if edge.access_path else None,
                "explanation": explain_edge(edge, source, target),
                "source": _node_summary(source),
                "target": _node_summary(target),
            }
        )
    return hops


def _summary_for_hops(hops: list[dict[str, Any]], *, is_toxic: bool) -> str:
    if not hops:
        return ""
    start_label = hops[0]["source"]["label"]
    end_label = hops[-1]["target"]["label"]
    end_type = hops[-1]["target"]["node_type"]
    n = len(hops)
    hop_word = "hop" if n == 1 else "hops"
    prefix = "Toxic combination path: " if is_toxic else "Access path: "
    if n == 1:
        return f"{prefix}{hops[0]['explanation'].rstrip('.')} ({n} {hop_word})."
    return (
        f"{prefix}from “{start_label}” to “{end_label}” ({end_type}) across {n} graph {hop_word} grounded in existing edges."
    )


def _is_system_toxic_finding(db: Session, finding: Finding) -> bool:
    from kestrel.db.models.policy import Policy, PolicyVersion
    from kestrel.findings.toxic_combo import is_system_toxic_policy

    version = db.get(PolicyVersion, finding.policy_version_id)
    if version is None:
        return False
    policy = db.get(Policy, version.policy_id)
    return is_system_toxic_policy(policy)


def attack_path(
    db: Session,
    finding: Finding,
    *,
    max_depth: int = ATTACK_PATH_DEPTH_DEFAULT,
) -> dict[str, Any]:
    """Ordered privilege-relevant path from the finding subject."""
    capped = max(1, min(max_depth, ATTACK_PATH_DEPTH_MAX))
    start = _subject_graph_node(db, finding)
    if start is None:
        return _empty_path(
            finding,
            subject_node_id=None,
            max_depth=capped,
            summary=(
                "No attack path: this finding's subject has no matching graph node "
                "(inventory may not have been synced into the access graph)."
            ),
        )

    # BFS: each queue item is (current_node_id, edge_path).
    queue: deque[tuple[uuid.UUID, list[GraphEdge]]] = deque([(start.id, [])])
    visited: set[uuid.UUID] = {start.id}
    candidates: list[list[GraphEdge]] = []
    nodes_cache: dict[uuid.UUID, GraphNode] = {start.id: start}
    saw_any_edge = False

    while queue:
        node_id, path = queue.popleft()
        if len(path) >= capped:
            continue
        for edge in _outgoing_edges(db, finding.org_id, node_id):
            saw_any_edge = True
            nxt = edge.target_node_id
            if nxt in visited:
                continue
            visited.add(nxt)
            new_path = [*path, edge]
            # Ensure target node is loadable before treating as a real hop.
            if nxt not in nodes_cache:
                loaded = _load_nodes(db, finding.org_id, {nxt})
                if nxt not in loaded:
                    continue
                nodes_cache.update(loaded)
            sink = _sink_score(db, nodes_cache[nxt])
            if sink > 0:
                candidates.append(new_path)
            queue.append((nxt, new_path))

    if not candidates:
        if not saw_any_edge:
            return _empty_path(
                finding,
                subject_node_id=start.id,
                max_depth=capped,
                summary=(f"No attack path: graph node “{start.label}” has no outbound edges within {capped} hops."),
            )
        return _empty_path(
            finding,
            subject_node_id=start.id,
            max_depth=capped,
            summary=(
                f"No privilege-relevant attack path from “{start.label}” within "
                f"{capped} hops (neighbors exist but none are role / OAuth / "
                "resource / permission / group sinks)."
            ),
        )

    # Ensure all path endpoints are in the cache for ranking + hop build.
    needed: set[uuid.UUID] = set()
    for path in candidates:
        for edge in path:
            needed.add(edge.source_node_id)
            needed.add(edge.target_node_id)
    nodes_cache.update(_load_nodes(db, finding.org_id, needed - set(nodes_cache)))

    best = max(candidates, key=lambda p: _path_rank(db, p, nodes_cache))
    hops = _build_hops(db, best, nodes_cache)
    if not hops:
        return _empty_path(
            finding,
            subject_node_id=start.id,
            max_depth=capped,
            summary=("No attack path: path edges referenced missing graph nodes; refusing to fabricate hops."),
        )

    toxic = _is_system_toxic_finding(db, finding)
    return {
        "finding_id": finding.id,
        "subject_node_id": start.id,
        "algorithm": ATTACK_PATH_ALGORITHM,
        "max_depth": capped,
        "hop_count": len(hops),
        "hops": hops,
        "summary": _summary_for_hops(hops, is_toxic=toxic),
    }


def attack_path_compact(path: dict[str, Any]) -> dict[str, Any]:
    """Compact shape for nesting on finding detail / handoff."""
    hop_count = int(path.get("hop_count") or 0)
    finding_id = path.get("finding_id")
    return {
        "available": hop_count > 0,
        "hop_count": hop_count,
        "summary": path.get("summary") or "",
        "algorithm": path.get("algorithm"),
        "subject_node_id": path.get("subject_node_id"),
        "hops": path.get("hops") or [],
        "path": f"/findings/{finding_id}/attack-path" if finding_id else None,
    }
