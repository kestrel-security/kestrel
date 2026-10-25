# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Graph traversal queries via recursive CTEs (see ADR-0003). Kept as raw
SQL rather than the ORM query builder since recursive CTEs aren't expressed
cleanly through SQLAlchemy Core/ORM constructs, and this is a hot enough path
(every "what can this identity access" question) to want a readable,
auditable query rather than a generated one.
"""

from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from kestrel.db.models.graph_edge import GraphNode, GraphNodeType
from kestrel.graph.models import GraphNodeRef

MAX_TRAVERSAL_DEPTH = 6
DEFAULT_SEARCH_LIMIT = 20
MAX_SEARCH_LIMIT = 50

TraversalDirection = Literal["out", "in", "both"]

_REACHABLE_OUT_SQL = text(
    """
    WITH RECURSIVE reach(node_id, depth, path) AS (
        SELECT gn.id, 0, ARRAY[gn.id]
        FROM graph_nodes gn
        WHERE gn.id = :start_node_id AND gn.org_id = :org_id
      UNION ALL
        SELECT ge.target_node_id, r.depth + 1, r.path || ge.target_node_id
        FROM graph_edges ge
        JOIN reach r ON ge.source_node_id = r.node_id
        WHERE r.depth < :max_depth
          AND NOT ge.target_node_id = ANY(r.path)
          AND ge.org_id = :org_id
    )
    SELECT DISTINCT gn.id, gn.node_type, gn.object_id, gn.label, gn.properties
    FROM reach r
    JOIN graph_nodes gn ON gn.id = r.node_id
    WHERE gn.id != :start_node_id
    """
)

_REACHABLE_IN_SQL = text(
    """
    WITH RECURSIVE reach(node_id, depth, path) AS (
        SELECT gn.id, 0, ARRAY[gn.id]
        FROM graph_nodes gn
        WHERE gn.id = :start_node_id AND gn.org_id = :org_id
      UNION ALL
        SELECT ge.source_node_id, r.depth + 1, r.path || ge.source_node_id
        FROM graph_edges ge
        JOIN reach r ON ge.target_node_id = r.node_id
        WHERE r.depth < :max_depth
          AND NOT ge.source_node_id = ANY(r.path)
          AND ge.org_id = :org_id
    )
    SELECT DISTINCT gn.id, gn.node_type, gn.object_id, gn.label, gn.properties
    FROM reach r
    JOIN graph_nodes gn ON gn.id = r.node_id
    WHERE gn.id != :start_node_id
    """
)

# Bidirectional: follow either endpoint of an incident edge each hop.
_REACHABLE_BOTH_SQL = text(
    """
    WITH RECURSIVE reach(node_id, depth, path) AS (
        SELECT gn.id, 0, ARRAY[gn.id]
        FROM graph_nodes gn
        WHERE gn.id = :start_node_id AND gn.org_id = :org_id
      UNION ALL
        SELECT nxt.next_id, r.depth + 1, r.path || nxt.next_id
        FROM reach r
        JOIN LATERAL (
            SELECT ge.target_node_id AS next_id
            FROM graph_edges ge
            WHERE ge.source_node_id = r.node_id AND ge.org_id = :org_id
            UNION ALL
            SELECT ge.source_node_id AS next_id
            FROM graph_edges ge
            WHERE ge.target_node_id = r.node_id AND ge.org_id = :org_id
        ) nxt ON true
        WHERE r.depth < :max_depth
          AND NOT nxt.next_id = ANY(r.path)
    )
    SELECT DISTINCT gn.id, gn.node_type, gn.object_id, gn.label, gn.properties
    FROM reach r
    JOIN graph_nodes gn ON gn.id = r.node_id
    WHERE gn.id != :start_node_id
    """
)

_DIRECTION_SQL = {
    "out": _REACHABLE_OUT_SQL,
    "in": _REACHABLE_IN_SQL,
    "both": _REACHABLE_BOTH_SQL,
}


def reachable_nodes(
    session: Session,
    *,
    org_id: uuid.UUID,
    start_node_id: uuid.UUID,
    max_depth: int = MAX_TRAVERSAL_DEPTH,
    direction: TraversalDirection = "out",
) -> list[GraphNodeRef]:
    """Every graph node reachable from `start_node_id` within `max_depth`
    hops -- answers "what can this identity access across every connected
    application, including group/role-inherited access".

    ``direction``:
    - ``out`` — follow source → target (default; prior behavior)
    - ``in`` — follow target → source (who points at this node)
    - ``both`` — bidirectional expansion each hop
    """
    if direction not in _DIRECTION_SQL:
        raise ValueError(f"Unknown traversal direction '{direction}'")
    rows = session.execute(
        _DIRECTION_SQL[direction],
        {"start_node_id": start_node_id, "org_id": org_id, "max_depth": max_depth},
    ).mappings()
    return [GraphNodeRef.from_row(dict(row)) for row in rows]


def neighbors(
    session: Session,
    *,
    org_id: uuid.UUID,
    node_id: uuid.UUID,
    depth: int = 1,
    direction: TraversalDirection = "out",
) -> list[GraphNodeRef]:
    """Bounded-depth neighbor expansion for the graph UI's click-to-expand
    interaction -- the same traversal as reachable_nodes, typically called
    with depth=1 for incremental exploration rather than full reachability."""
    return reachable_nodes(
        session,
        org_id=org_id,
        start_node_id=node_id,
        max_depth=depth,
        direction=direction,
    )


def search_nodes(
    session: Session,
    *,
    org_id: uuid.UUID,
    q: str,
    node_types: list[GraphNodeType] | None = None,
    limit: int = DEFAULT_SEARCH_LIMIT,
) -> list[GraphNode]:
    """Org-scoped label search for the Access Graph workbench picker.

    Matches ``GraphNode.label ILIKE %q%``, optionally restricted to
    ``node_types``, ordered by label, capped at ``MAX_SEARCH_LIMIT``.
    """
    capped = max(1, min(limit, MAX_SEARCH_LIMIT))
    pattern = f"%{q}%"
    stmt = (
        select(GraphNode)
        .where(GraphNode.org_id == org_id, GraphNode.label.ilike(pattern))
        .order_by(GraphNode.label.asc(), GraphNode.id.asc())
        .limit(capped)
    )
    if node_types:
        stmt = stmt.where(GraphNode.node_type.in_(node_types))
    return list(session.scalars(stmt).all())


def privileged_identity_ids_subquery(org_id: uuid.UUID):
    """A SELECT of identity ids holding at least one privileged role.

    "Privileged" is defined by the graph, not the grants table: an identity
    is privileged when it has an `assigned_role` edge to a Role with
    `is_privileged = true`. Grants describe access to a *resource* (a repo,
    a drive) and frequently carry no role at all -- the GitHub connector's
    grants, for instance, never set `role_id` -- so joining through
    `Grant.role_id` silently matches nothing. This mirrors how the policy
    engine resolves the `roles` virtual field (see
    historical policy dataload helpers), so the API's `privileged`
    filter and Python policy `roles` checks agree on the same truth.

    Returned as a subquery rather than a list of ids so callers can use it
    inside a larger statement -- pagination requires the filter to be part
    of the SQL, applied before LIMIT.
    """
    from sqlalchemy.orm import aliased

    from kestrel.db.models.access import Role
    from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType

    identity_node = aliased(GraphNode)
    role_node = aliased(GraphNode)

    return (
        select(identity_node.object_id)
        .join(GraphEdge, GraphEdge.source_node_id == identity_node.id)
        .join(role_node, role_node.id == GraphEdge.target_node_id)
        .join(Role, Role.id == role_node.object_id)
        .where(
            identity_node.org_id == org_id,
            identity_node.node_type == GraphNodeType.IDENTITY,
            GraphEdge.org_id == org_id,
            GraphEdge.edge_type == GraphEdgeType.ASSIGNED_ROLE,
            role_node.node_type == GraphNodeType.ROLE,
            Role.is_privileged.is_(True),
        )
    )
