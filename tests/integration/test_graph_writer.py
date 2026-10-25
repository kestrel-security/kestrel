# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- ``graph.writer`` node/edge upserts.

Drives ``upsert_nodes``/``upsert_edges`` directly against a hand-built
``UpsertContext`` and a list of ``NormalizedObject``s -- the graph writer's
contract (direct vs inherited vs OAuth-derived access paths land as distinct
edges; re-upserting is idempotent; a batch never double-inserts the same
edge) doesn't need a full sync run to exercise, and testing it directly
keeps these tests fast and independent of any connector's normalizer.
"""

from __future__ import annotations

import uuid

from kestrel.connectors.sdk.base import NormalizedObject, NormalizedRelationship
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.graph.writer import upsert_edges, upsert_nodes
from kestrel.sync.upsert import UpsertContext, upsert_provenance_objects, upsert_relationship_objects
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


def _new_run(session: Session, org_id: uuid.UUID, connector_instance_id: uuid.UUID) -> ConnectorRun:
    from datetime import UTC, datetime

    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=org_id,
        connector_instance_id=connector_instance_id,
        status=ConnectorRunStatus.RUNNING,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    session.add(run)
    session.flush()
    return run


def _apply(session: Session, ctx: UpsertContext, objects: list[NormalizedObject]) -> dict:
    """Run the same two-pass upsert run_sync uses (provenance, then
    relationships, then graph), returning the node id maps."""
    upsert_provenance_objects(session, objects, ctx)
    session.flush()
    node_id_maps = upsert_nodes(session, objects, ctx)
    upsert_relationship_objects(session, objects, ctx)
    session.flush()
    upsert_edges(session, objects, ctx, node_id_maps)
    session.flush()
    return node_id_maps


class _Fixture:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()

    def ctx(self) -> UpsertContext:
        run = _new_run(self.session, self.org.id, self.connector_instance.id)
        return UpsertContext(
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            connector_run_id=run.id,
            connector_instance_id=self.connector_instance.id,
        )


def test_upsert_nodes_creates_one_node_per_provenance_object(db_session: Session):
    fx = _Fixture(db_session)
    ctx = fx.ctx()
    objects = [
        NormalizedObject(
            kind="identity",
            provider_id="i1",
            attributes={"identity_type": "user", "display_name": "I1"},
            raw_source={},
        ),
        NormalizedObject(kind="group", provider_id="g1", attributes={"name": "G1"}, raw_source={}),
    ]
    _apply(db_session, ctx, objects)

    nodes = db_session.scalars(select(GraphNode).where(GraphNode.org_id == fx.org.id)).all()
    assert {n.node_type for n in nodes} == {GraphNodeType.IDENTITY, GraphNodeType.GROUP}
    labels = {n.label for n in nodes}
    assert labels == {"I1", "G1"}


def test_upsert_nodes_is_idempotent_and_updates_label(db_session: Session):
    fx = _Fixture(db_session)
    ctx1 = fx.ctx()
    objects_v1 = [NormalizedObject(kind="group", provider_id="g1", attributes={"name": "Original"}, raw_source={})]
    _apply(db_session, ctx1, objects_v1)

    ctx2 = fx.ctx()
    objects_v2 = [NormalizedObject(kind="group", provider_id="g1", attributes={"name": "Renamed"}, raw_source={})]
    _apply(db_session, ctx2, objects_v2)

    nodes = db_session.scalars(
        select(GraphNode).where(GraphNode.org_id == fx.org.id, GraphNode.node_type == GraphNodeType.GROUP)
    ).all()
    assert len(nodes) == 1
    assert nodes[0].label == "Renamed"


def test_upsert_edges_distinguishes_direct_inherited_and_oauth_derived_access(db_session: Session):
    """Same edge_type (assigned_role), three different access_path values --
    the invariant Explore and the policy dataload layer both depend on."""
    fx = _Fixture(db_session)
    ctx = fx.ctx()

    direct_identity = NormalizedObject(
        kind="identity",
        provider_id="direct-user",
        attributes={"identity_type": "user", "display_name": "Direct"},
        raw_source={},
        relationships=[
            NormalizedRelationship(
                edge_type="assigned_role", source_ref="direct-user", target_ref="role-1", access_path="direct"
            ),
        ],
    )
    inherited_identity = NormalizedObject(
        kind="identity",
        provider_id="inherited-user",
        attributes={"identity_type": "user", "display_name": "Inherited"},
        raw_source={},
        relationships=[
            NormalizedRelationship(
                edge_type="assigned_role", source_ref="inherited-user", target_ref="role-1", access_path="inherited_group"
            ),
        ],
    )
    oauth_identity = NormalizedObject(
        kind="identity",
        provider_id="oauth-user",
        attributes={"identity_type": "user", "display_name": "OAuth"},
        raw_source={},
        relationships=[
            NormalizedRelationship(
                edge_type="can_access", source_ref="oauth-user", target_ref="resource-1", access_path="oauth_derived"
            ),
        ],
    )
    role = NormalizedObject(
        kind="role", provider_id="role-1", attributes={"name": "Role", "is_privileged": True}, raw_source={}
    )
    resource = NormalizedObject(
        kind="resource", provider_id="resource-1", attributes={"resource_type": "repository", "name": "Res"}, raw_source={}
    )

    _apply(db_session, ctx, [direct_identity, inherited_identity, oauth_identity, role, resource])

    edges = db_session.scalars(select(GraphEdge).where(GraphEdge.org_id == fx.org.id)).all()
    access_paths = {e.access_path for e in edges}
    assert access_paths == {AccessPath.DIRECT, AccessPath.INHERITED_GROUP, AccessPath.OAUTH_DERIVED}

    role_edges = [e for e in edges if e.edge_type is GraphEdgeType.ASSIGNED_ROLE]
    assert {e.access_path for e in role_edges} == {AccessPath.DIRECT, AccessPath.INHERITED_GROUP}
    # Both point at the same role node -- the same identity could hold a role
    # both directly and via a group without one overwriting the other.
    assert len({e.target_node_id for e in role_edges}) == 1


def test_upsert_edges_deduplicates_repeated_relationship_within_one_batch(db_session: Session):
    fx = _Fixture(db_session)
    ctx = fx.ctx()

    # Two objects in the same run both declare the identical edge -- e.g. a
    # connector's normalizer emitting the same membership from two API calls.
    identity = NormalizedObject(
        kind="identity",
        provider_id="u1",
        attributes={"identity_type": "user", "display_name": "U1"},
        raw_source={},
        relationships=[
            NormalizedRelationship(edge_type="member_of", source_ref="u1", target_ref="g1"),
            NormalizedRelationship(edge_type="member_of", source_ref="u1", target_ref="g1"),
        ],
    )
    group = NormalizedObject(kind="group", provider_id="g1", attributes={"name": "G1"}, raw_source={})

    _apply(db_session, ctx, [identity, group])

    edges = db_session.scalars(select(GraphEdge).where(GraphEdge.org_id == fx.org.id)).all()
    assert len(edges) == 1


def test_upsert_edges_skips_relationship_referencing_object_outside_this_run(db_session: Session):
    """A relationship pointing at a provider_id this run never normalized
    (e.g. a partial/incremental sync) is skipped rather than raising."""
    fx = _Fixture(db_session)
    ctx = fx.ctx()

    identity = NormalizedObject(
        kind="identity",
        provider_id="u1",
        attributes={"identity_type": "user", "display_name": "U1"},
        raw_source={},
        relationships=[
            NormalizedRelationship(edge_type="member_of", source_ref="u1", target_ref="does-not-exist-this-run"),
        ],
    )

    _apply(db_session, ctx, [identity])

    edges = db_session.scalars(select(GraphEdge).where(GraphEdge.org_id == fx.org.id)).all()
    assert edges == []
