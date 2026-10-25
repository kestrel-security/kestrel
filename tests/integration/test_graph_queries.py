# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- ``graph.queries`` traversal (recursive CTEs).

Builds ``GraphNode``/``GraphEdge`` rows directly rather than through a sync
run: these queries are pure reads over the graph read-model, so the test
only needs rows shaped correctly, not a connector behind them. This is what
Explore's "what can this identity reach" and the policy engine's
``privileged`` filter both depend on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kestrel.db.models.access import Role
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.graph.queries import neighbors, privileged_identity_ids_subquery, reachable_nodes, search_nodes
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy.orm import Session


class _Graph:
    """Small helper for wiring up GraphNode/GraphEdge rows in a test."""

    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()
        self._run_id = self.connector_instance.id  # any UUID works; source_connector_run_id has no FK check here

    def identity(self, *, label: str, email: str | None = None) -> tuple[Identity, GraphNode]:
        row = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            provider_object_id=f"identity-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=email,
            display_name=label,
            source_connector_run_id=self._connector_run_id(),
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        node = self._node(GraphNodeType.IDENTITY, row.id, label)
        return row, node

    def role(self, *, label: str, is_privileged: bool = False) -> tuple[Role, GraphNode]:
        row = Role(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            provider_object_id=f"role-{uuid.uuid4().hex[:8]}",
            name=label,
            is_privileged=is_privileged,
            source_connector_run_id=self._connector_run_id(),
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        node = self._node(GraphNodeType.ROLE, row.id, label)
        return row, node

    def group_node(self, *, label: str) -> GraphNode:
        # A bare GraphNode is enough for pure traversal tests -- reachable_nodes
        # never joins back to the groups table.
        return self._node(GraphNodeType.GROUP, uuid.uuid4(), label)

    def _connector_run_id(self) -> uuid.UUID:
        from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.connector_instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def _node(self, node_type: GraphNodeType, object_id: uuid.UUID, label: str) -> GraphNode:
        node = GraphNode(
            id=uuid.uuid4(), org_id=self.org.id, node_type=node_type, object_id=object_id, label=label, properties={}
        )
        self.session.add(node)
        self.session.flush()
        return node

    def edge(
        self,
        source: GraphNode,
        target: GraphNode,
        edge_type: GraphEdgeType,
        *,
        access_path: AccessPath | None = None,
    ) -> GraphEdge:
        edge = GraphEdge(
            id=uuid.uuid4(),
            org_id=self.org.id,
            source_node_id=source.id,
            target_node_id=target.id,
            edge_type=edge_type,
            access_path=access_path,
            source_connector_run_id=self._connector_run_id(),
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
            properties={},
        )
        self.session.add(edge)
        self.session.flush()
        return edge


def test_reachable_nodes_follows_direct_and_inherited_multi_hop_edges(db_session: Session):
    g = _Graph(db_session)
    _, identity_node = g.identity(label="Identity")
    group_node = g.group_node(label="Group")
    _, role_node = g.role(label="Role")

    g.edge(identity_node, group_node, GraphEdgeType.MEMBER_OF)
    g.edge(group_node, role_node, GraphEdgeType.ASSIGNED_ROLE, access_path=AccessPath.INHERITED_GROUP)

    reachable = reachable_nodes(db_session, org_id=g.org.id, start_node_id=identity_node.id, direction="out")
    reachable_ids = {n.id for n in reachable}
    assert group_node.id in reachable_ids
    assert role_node.id in reachable_ids
    # The starting node itself is never included.
    assert identity_node.id not in reachable_ids


def test_reachable_nodes_respects_max_depth(db_session: Session):
    g = _Graph(db_session)
    _, identity_node = g.identity(label="Identity")
    group_node = g.group_node(label="Group")
    _, role_node = g.role(label="Role")
    g.edge(identity_node, group_node, GraphEdgeType.MEMBER_OF)
    g.edge(group_node, role_node, GraphEdgeType.ASSIGNED_ROLE)

    one_hop = reachable_nodes(db_session, org_id=g.org.id, start_node_id=identity_node.id, max_depth=1, direction="out")
    one_hop_ids = {n.id for n in one_hop}
    assert one_hop_ids == {group_node.id}


def test_reachable_nodes_direction_in_finds_who_points_at_a_node(db_session: Session):
    g = _Graph(db_session)
    _, identity_node = g.identity(label="Identity")
    _, role_node = g.role(label="Role")
    g.edge(identity_node, role_node, GraphEdgeType.ASSIGNED_ROLE, access_path=AccessPath.DIRECT)

    who_holds_role = reachable_nodes(db_session, org_id=g.org.id, start_node_id=role_node.id, direction="in")
    assert {n.id for n in who_holds_role} == {identity_node.id}


def test_neighbors_is_depth_one_reachability(db_session: Session):
    g = _Graph(db_session)
    _, identity_node = g.identity(label="Identity")
    group_node = g.group_node(label="Group")
    _, role_node = g.role(label="Role")
    g.edge(identity_node, group_node, GraphEdgeType.MEMBER_OF)
    g.edge(group_node, role_node, GraphEdgeType.ASSIGNED_ROLE)

    direct_neighbors = neighbors(db_session, org_id=g.org.id, node_id=identity_node.id, depth=1)
    assert {n.id for n in direct_neighbors} == {group_node.id}


def test_search_nodes_matches_label_and_filters_by_type(db_session: Session):
    g = _Graph(db_session)
    _, identity_node = g.identity(label="Findable Person")
    _, role_node = g.role(label="Findable Role")
    g.group_node(label="Unrelated Group")

    results = search_nodes(db_session, org_id=g.org.id, q="Findable")
    assert {n.id for n in results} == {identity_node.id, role_node.id}

    identity_only = search_nodes(db_session, org_id=g.org.id, q="Findable", node_types=[GraphNodeType.IDENTITY])
    assert {n.id for n in identity_only} == {identity_node.id}


def test_search_nodes_is_scoped_to_org(db_session: Session):
    g1 = _Graph(db_session)
    g2 = _Graph(db_session)
    g1.identity(label="Shared Label")
    g2.identity(label="Shared Label")

    results = search_nodes(db_session, org_id=g1.org.id, q="Shared Label")
    assert len(results) == 1


def test_privileged_identity_ids_subquery_matches_only_privileged_role_assignments(db_session: Session):
    g = _Graph(db_session)
    privileged_identity, privileged_identity_node = g.identity(label="Privileged")
    plain_identity, plain_identity_node = g.identity(label="Plain")
    _, privileged_role_node = g.role(label="Admin Role", is_privileged=True)
    _, plain_role_node = g.role(label="Read Role", is_privileged=False)

    g.edge(privileged_identity_node, privileged_role_node, GraphEdgeType.ASSIGNED_ROLE, access_path=AccessPath.DIRECT)
    g.edge(plain_identity_node, plain_role_node, GraphEdgeType.ASSIGNED_ROLE, access_path=AccessPath.DIRECT)

    statement = privileged_identity_ids_subquery(g.org.id)
    matched_ids = set(db_session.scalars(statement).all())

    assert matched_ids == {privileged_identity.id}
    assert plain_identity.id not in matched_ids
