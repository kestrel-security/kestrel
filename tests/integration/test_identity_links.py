# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- persisted cross-app identity correlation (``identity_links``).

Correlation used to be recomputed over every identity in the org on each read.
These tests pin the materialized form: one row per identity naming its
cluster, rebuilt by the sync pipeline, and read paths that agree with the
in-memory computation they replaced.
"""

from __future__ import annotations

import uuid

from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.identity_link import IdentityLink
from kestrel.graph.writer import write_identity_link_edges
from kestrel.identities.correlate import (
    collapse_identity_search_hits,
    identity_cluster_for,
    rebuild_identity_links,
)
from kestrel.testing import make_application, make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


class _World:
    """Two application instances of different types in one org."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.org = make_organization(session)
        self.instances: dict[str, object] = {}
        self.runs: dict[str, uuid.UUID] = {}

    def instance(self, app_type: str):
        if app_type not in self.instances:
            from kestrel.db.models.application import ApplicationType

            application = make_application(self.session, self.org, application_type=ApplicationType(app_type))
            app_instance = make_application_instance(self.session, self.org, application=application)
            connector = make_connector_instance(self.session, self.org, application_instance=app_instance)
            self.session.flush()
            self.instances[app_type] = app_instance
            self.runs[app_type] = self._run(connector)
        return self.instances[app_type]

    def _run(self, connector_instance) -> uuid.UUID:
        from datetime import UTC, datetime

        from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=connector_instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def identity(self, app_type: str, *, email: str | None, display_name: str) -> Identity:
        app_instance = self.instance(app_type)
        row = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=app_instance.id,
            provider_object_id=f"{app_type}-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=email,
            display_name=display_name,
            source_connector_run_id=self.runs[app_type],
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        return row

    def node_for(self, identity: Identity) -> GraphNode:
        node = GraphNode(
            id=uuid.uuid4(),
            org_id=self.org.id,
            node_type=GraphNodeType.IDENTITY,
            object_id=identity.id,
            label=identity.display_name or "",
            properties={},
        )
        self.session.add(node)
        self.session.flush()
        return node


def test_shared_email_across_applications_becomes_one_cluster(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="grace@acme.test", display_name="Grace Hopper")
    github = world.identity("github", email="grace@acme.test", display_name="ghopper")
    alone = world.identity("slack", email="someone.else@acme.test", display_name="Someone Else")

    written = rebuild_identity_links(db_session, org_id=world.org.id)

    assert written == 3
    links = {
        link.identity_id: link
        for link in db_session.scalars(select(IdentityLink).where(IdentityLink.org_id == world.org.id)).all()
    }
    assert links[okta.id].cluster_key == links[github.id].cluster_key
    assert links[okta.id].member_count == 2
    assert links[okta.id].match_kind == "email"
    assert sorted(links[okta.id].application_types) == ["github", "okta"]
    assert links[alone.id].member_count == 1
    assert links[alone.id].match_kind == "self"
    # The IdP account represents the person.
    assert links[github.id].representative_identity_id == okta.id


def test_the_materialized_cluster_matches_the_in_memory_one(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="ada@acme.test", display_name="Ada Lovelace")
    world.identity("github", email="ada@acme.test", display_name="alovelace")

    before = identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)
    rebuild_identity_links(db_session, org_id=world.org.id)
    after = identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)

    assert before is not None
    assert after is not None
    assert sorted(after["identity_ids"]) == sorted(before["identity_ids"])
    assert after["application_types"] == before["application_types"]
    assert after["member_count"] == before["member_count"] == 2


def test_search_collapse_agrees_with_the_materialized_links(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="alan@acme.test", display_name="Alan Turing")
    github = world.identity("github", email="alan@acme.test", display_name="aturing")
    rebuild_identity_links(db_session, org_id=world.org.id)

    collapsed = collapse_identity_search_hits(db_session, org_id=world.org.id, identity_object_ids=[github.id])

    assert collapsed[github.id]["member_count"] == 2
    assert collapsed[github.id]["representative_identity_id"] == okta.id
    assert sorted(collapsed[github.id]["application_types"]) == ["github", "okta"]


def test_a_rebuild_replaces_a_cluster_that_split(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="pat@acme.test", display_name="Pat Example")
    github = world.identity("github", email="pat@acme.test", display_name="pexample")
    rebuild_identity_links(db_session, org_id=world.org.id)
    assert identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)["member_count"] == 2

    # The GitHub account's email is corrected to someone else's.
    github.email = "different.person@acme.test"
    github.display_name = "dperson"
    db_session.flush()
    rebuild_identity_links(db_session, org_id=world.org.id)

    assert identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)["member_count"] == 1
    assert identity_cluster_for(db_session, org_id=world.org.id, identity_id=github.id)["member_count"] == 1


def test_a_tombstoned_account_leaves_the_cluster(db_session: Session):
    from datetime import UTC, datetime

    world = _World(db_session)
    okta = world.identity("okta", email="gone@acme.test", display_name="Gone Person")
    github = world.identity("github", email="gone@acme.test", display_name="gperson")
    rebuild_identity_links(db_session, org_id=world.org.id)
    assert identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)["member_count"] == 2

    github.deleted_at = datetime.now(UTC)
    db_session.flush()
    rebuild_identity_links(db_session, org_id=world.org.id)

    assert identity_cluster_for(db_session, org_id=world.org.id, identity_id=okta.id)["member_count"] == 1
    assert (
        db_session.scalar(
            select(IdentityLink).where(IdentityLink.org_id == world.org.id, IdentityLink.identity_id == github.id)
        )
        is None
    )


def test_correlated_accounts_are_joined_by_a_federated_graph_edge(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="grace@acme.test", display_name="Grace Hopper")
    github = world.identity("github", email="grace@acme.test", display_name="ghopper")
    okta_node = world.node_for(okta)
    github_node = world.node_for(github)
    rebuild_identity_links(db_session, org_id=world.org.id)

    written = write_identity_link_edges(db_session, org_id=world.org.id)

    assert written == 1
    edge = db_session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == world.org.id, GraphEdge.edge_type == GraphEdgeType.MAPS_TO)
    ).one()
    assert (edge.source_node_id, edge.target_node_id) == (okta_node.id, github_node.id)
    assert edge.access_path is AccessPath.FEDERATED
    assert edge.properties["match_kind"] == "email"


def test_a_split_cluster_removes_its_federated_edge(db_session: Session):
    world = _World(db_session)
    okta = world.identity("okta", email="pair@acme.test", display_name="Pair Person")
    github = world.identity("github", email="pair@acme.test", display_name="pperson")
    world.node_for(okta)
    world.node_for(github)
    rebuild_identity_links(db_session, org_id=world.org.id)
    write_identity_link_edges(db_session, org_id=world.org.id)

    github.email = "unrelated@acme.test"
    github.display_name = "unrelated"
    db_session.flush()
    rebuild_identity_links(db_session, org_id=world.org.id)
    assert write_identity_link_edges(db_session, org_id=world.org.id) == 0

    assert (
        db_session.scalars(
            select(GraphEdge).where(GraphEdge.org_id == world.org.id, GraphEdge.edge_type == GraphEdgeType.MAPS_TO)
        ).all()
        == []
    )
