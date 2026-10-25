# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- Explore traversal (``graph.explore``) does bounded work.

The bug this guards: ``neighbor_subgraph`` and ``reachability_paths`` ran one
query per visited node with no visit cap, and applied ``max_nodes`` / ``limit``
only after the traversal, so ``direction=both&depth=3`` on a hub group walked
most of the graph. The traversal now runs frontier-at-a-time (one query per
depth level) and stops at a visit cap derived from the requested output size,
reporting ``truncated``.

Rows are bare ``GraphNode`` / ``GraphEdge`` rows the test owns; traversal never
joins back to the entity tables. Group and resource nodes keep the identity
cluster lookup out of the picture.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.graph.explore import neighbor_subgraph, reachability_paths
from kestrel.testing import make_organization
from sqlalchemy import event
from sqlalchemy.orm import Session


class _Graph:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        session.flush()
        self._pending_edges: list[GraphEdge] = []

    def node(self, node_type: GraphNodeType, label: str) -> GraphNode:
        node = GraphNode(
            id=uuid.uuid4(),
            org_id=self.org.id,
            node_type=node_type,
            object_id=uuid.uuid4(),
            label=label,
            properties={},
        )
        self.session.add(node)
        return node

    def edge(self, source: GraphNode, target: GraphNode, edge_type: GraphEdgeType) -> GraphEdge:
        edge = GraphEdge(
            id=uuid.uuid4(),
            org_id=self.org.id,
            source_node_id=source.id,
            target_node_id=target.id,
            edge_type=edge_type,
            access_path=AccessPath.DIRECT,
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
            properties={},
        )
        # No ORM relationship orders node inserts before edge inserts, so
        # edges wait for flush().
        self._pending_edges.append(edge)
        return edge

    def flush(self) -> None:
        self.session.flush()
        self.session.add_all(self._pending_edges)
        self._pending_edges = []
        self.session.flush()

    def hub(self, members: int) -> GraphNode:
        """A group with ``members`` identities, each of which also reaches its own resource."""
        group = self.node(GraphNodeType.GROUP, "Everyone")
        for index in range(members):
            member = self.node(GraphNodeType.IDENTITY, f"member-{index:04d}")
            resource = self.node(GraphNodeType.RESOURCE, f"repo-{index:04d}")
            self.edge(member, group, GraphEdgeType.MEMBER_OF)
            self.edge(member, resource, GraphEdgeType.CAN_ACCESS)
        self.flush()
        return group


class _SqlCounter:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.rows_by_table: dict[str, int] = {}

    def edge_queries(self) -> int:
        return sum(1 for sql in self.statements if sql.lstrip().upper().startswith("SELECT") and "graph_edges" in sql)


@contextmanager
def _count_sql(session: Session) -> Iterator[_SqlCounter]:
    counter = _SqlCounter()
    connection = session.connection()

    def before(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        counter.statements.append(statement)

    def after(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        match = re.match(r"\s*SELECT\b.*?\bFROM\s+(\w+)", statement, re.IGNORECASE | re.DOTALL)
        if match:
            table = match.group(1).lower()
            counter.rows_by_table[table] = counter.rows_by_table.get(table, 0) + max(cursor.rowcount, 0)

    event.listen(connection, "before_cursor_execute", before)
    event.listen(connection, "after_cursor_execute", after)
    try:
        yield counter
    finally:
        event.remove(connection, "before_cursor_execute", before)
        event.remove(connection, "after_cursor_execute", after)


def test_neighbors_on_a_chain_still_returns_every_node_within_depth(db_session: Session):
    graph = _Graph(db_session)
    a = graph.node(GraphNodeType.GROUP, "a")
    b = graph.node(GraphNodeType.GROUP, "b")
    c = graph.node(GraphNodeType.GROUP, "c")
    d = graph.node(GraphNodeType.GROUP, "d")
    graph.edge(a, b, GraphEdgeType.MEMBER_OF)
    graph.edge(b, c, GraphEdgeType.MEMBER_OF)
    graph.edge(c, d, GraphEdgeType.MEMBER_OF)
    graph.flush()

    result = neighbor_subgraph(db_session, org_id=graph.org.id, start=a, depth=2, direction="out")

    assert {n["label"] for n in result["nodes"]} == {"a", "b", "c"}
    assert result["truncated"] is False


def test_neighbor_traversal_issues_one_edge_query_per_depth_level(db_session: Session):
    graph = _Graph(db_session)
    group = graph.hub(members=30)

    with _count_sql(db_session) as sql:
        result = neighbor_subgraph(db_session, org_id=graph.org.id, start=group, depth=3, direction="both")

    # 30 members plus 30 resources, all within reach.
    assert result["node_count"] == 61
    assert result["truncated"] is False
    # One query per depth level, plus the one that loads edges among the
    # visible nodes. The old per-node walk issued two per visited node.
    assert sql.edge_queries() <= 3 + 1


def test_a_hub_group_stops_at_the_visit_cap_and_says_truncated(db_session: Session):
    graph = _Graph(db_session)
    group = graph.hub(members=600)

    with _count_sql(db_session) as sql:
        result = neighbor_subgraph(db_session, org_id=graph.org.id, start=group, depth=3, direction="both", max_nodes=10)

    assert result["truncated"] is True
    assert result["node_count"] <= 10
    # Work is bounded by max_nodes too, not just output: far fewer than the
    # 1,200 nodes behind the hub were ever loaded.
    assert sql.rows_by_table.get("graph_nodes", 0) < 200
    assert sql.rows_by_table.get("graph_edges", 0) < 1000


def test_reachability_on_a_hub_stops_at_the_visit_cap_and_says_truncated(db_session: Session):
    graph = _Graph(db_session)
    group = graph.hub(members=600)

    with _count_sql(db_session) as sql:
        result = reachability_paths(db_session, org_id=graph.org.id, start=group, depth=3, direction="in", limit=5)

    assert result["truncated"] is True
    assert result["returned"] == 5
    assert sql.edge_queries() <= 3 + 1
    assert sql.rows_by_table.get("graph_nodes", 0) < 200
    assert sql.rows_by_table.get("graph_edges", 0) < 1000


def test_reachability_paths_are_still_shortest_paths(db_session: Session):
    graph = _Graph(db_session)
    start = graph.node(GraphNodeType.GROUP, "start")
    mid = graph.node(GraphNodeType.GROUP, "mid")
    far = graph.node(GraphNodeType.RESOURCE, "far")
    graph.edge(start, mid, GraphEdgeType.MEMBER_OF)
    graph.edge(mid, far, GraphEdgeType.CAN_ACCESS)
    graph.edge(start, far, GraphEdgeType.CAN_ACCESS)  # the one-hop shortcut
    graph.flush()

    result = reachability_paths(db_session, org_id=graph.org.id, start=start, depth=3, direction="out")

    hops = {p["destination"]["label"]: p["hop_count"] for p in result["paths"]}
    assert hops == {"mid": 1, "far": 1}
    assert result["truncated"] is False
