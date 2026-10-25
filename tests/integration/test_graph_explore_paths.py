# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- Explore neighbour subgraphs, reachability paths and search over a hand-built graph.

``test_graph_explore.py`` covers bounded work on hubs; this file covers what
the walk returns: correlated identity accounts collapsed onto the focus node,
OAuth scopes attached to ``possesses_scope`` edges, type and access-path
filters, path ordering and explanation, and search de-duplication.

The world is one person with an Okta and a GitHub account sharing an email:

    okta "Ada Lovelace" --member_of/direct--> group "Engineers" --can_access/inherited_group--> "repo-a"
    okta "Ada Lovelace" --assigned_role/inherited_role--> role "Org Admin"
    github "ada-octo"   --can_access/direct--> "repo-b"
    github "ada-octo"   --possesses_scope/oauth_derived--> oauth app "Deploy Bot"
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from kestrel.db.models.application import ApplicationType
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.oauth import OAuthApplication, OAuthScope
from kestrel.graph.explore import (
    get_org_node,
    neighbor_subgraph,
    reachability_paths,
    resolve_node,
    search_graph_nodes,
)
from kestrel.testing import make_application, make_application_instance, make_connector_instance, make_organization
from sqlalchemy.orm import Session

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _World:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.org = make_organization(session)
        self._pending_edges: list[GraphEdge] = []
        self._instances: dict[ApplicationType, tuple[uuid.UUID, uuid.UUID]] = {}

    def _instance(self, app_type: ApplicationType) -> tuple[uuid.UUID, uuid.UUID]:
        if app_type not in self._instances:
            application = make_application(self.session, self.org, application_type=app_type, name=app_type.value)
            app_instance = make_application_instance(self.session, self.org, application=application)
            connector = make_connector_instance(self.session, self.org, application_instance=app_instance)
            run = ConnectorRun(
                id=uuid.uuid4(),
                org_id=self.org.id,
                connector_instance_id=connector.id,
                status=ConnectorRunStatus.SUCCESS,
                started_at=NOW,
                triggered_by=ConnectorRunTrigger.MANUAL,
            )
            self.session.add(run)
            self.session.flush()
            self._instances[app_type] = (app_instance.id, run.id)
        return self._instances[app_type]

    def identity(self, app_type: ApplicationType, *, email: str, display_name: str, label: str) -> GraphNode:
        instance_id, run_id = self._instance(app_type)
        row = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=instance_id,
            provider_object_id=f"{app_type.value}-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=email,
            display_name=display_name,
            source_connector_run_id=run_id,
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        return self.node(GraphNodeType.IDENTITY, label, object_id=row.id)

    def oauth_app(self, name: str, scopes: list[tuple[str, bool]]) -> GraphNode:
        instance_id, run_id = self._instance(ApplicationType.GITHUB)
        app = OAuthApplication(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=instance_id,
            provider_object_id=f"oauth-{uuid.uuid4().hex[:8]}",
            name=name,
            source_connector_run_id=run_id,
            raw_source={},
        )
        self.session.add(app)
        self.session.flush()
        for scope_name, sensitive in scopes:
            self.session.add(
                OAuthScope(
                    id=uuid.uuid4(),
                    org_id=self.org.id,
                    oauth_application_id=app.id,
                    scope_name=scope_name,
                    is_sensitive=sensitive,
                )
            )
        return self.node(GraphNodeType.OAUTH_APPLICATION, name, object_id=app.id)

    def node(self, node_type: GraphNodeType, label: str, *, object_id: uuid.UUID | None = None) -> GraphNode:
        node = GraphNode(
            id=uuid.uuid4(),
            org_id=self.org.id,
            node_type=node_type,
            object_id=object_id or uuid.uuid4(),
            label=label,
            properties={},
        )
        self.session.add(node)
        return node

    def edge(
        self,
        source: GraphNode,
        target: GraphNode,
        edge_type: GraphEdgeType,
        access_path: AccessPath = AccessPath.DIRECT,
        properties: dict | None = None,
    ) -> GraphEdge:
        edge = GraphEdge(
            id=uuid.uuid4(),
            org_id=self.org.id,
            source_node_id=source.id,
            target_node_id=target.id,
            edge_type=edge_type,
            access_path=access_path,
            first_seen_at=NOW,
            last_seen_at=NOW,
            properties=properties or {},
        )
        self._pending_edges.append(edge)
        return edge

    def flush(self) -> None:
        self.session.flush()
        self.session.add_all(self._pending_edges)
        self._pending_edges = []
        self.session.flush()


class _Ada:
    def __init__(self, session: Session) -> None:
        w = self.world = _World(session)
        self.okta = w.identity(
            ApplicationType.OKTA, email="ada@example.test", display_name="Ada Lovelace", label="Ada Lovelace"
        )
        self.github = w.identity(ApplicationType.GITHUB, email="ADA@example.test", display_name="ada-octo", label="ada-octo")
        self.group = w.node(GraphNodeType.GROUP, "Engineers")
        self.role = w.node(GraphNodeType.ROLE, "Org Admin")
        self.repo_a = w.node(GraphNodeType.RESOURCE, "repo-a")
        self.repo_b = w.node(GraphNodeType.RESOURCE, "repo-b")
        self.bot = w.oauth_app("Deploy Bot", [("repo", True), ("read:user", False)])
        w.edge(self.okta, self.group, GraphEdgeType.MEMBER_OF)
        w.edge(self.group, self.repo_a, GraphEdgeType.CAN_ACCESS, AccessPath.INHERITED_GROUP)
        w.edge(self.okta, self.role, GraphEdgeType.ASSIGNED_ROLE, AccessPath.INHERITED_ROLE)
        w.edge(
            self.github,
            self.repo_b,
            GraphEdgeType.CAN_ACCESS,
            AccessPath.DIRECT,
            properties={"permission_level": "admin"},
        )
        w.edge(self.github, self.bot, GraphEdgeType.POSSESSES_SCOPE, AccessPath.OAUTH_DERIVED)
        w.flush()

    @property
    def org_id(self) -> uuid.UUID:
        return self.world.org.id


@pytest.fixture
def ada(db_session: Session) -> _Ada:
    return _Ada(db_session)


def _labels(nodes: list[dict]) -> set[str]:
    return {n["label"] for n in nodes}


def test_neighbors_of_an_identity_include_its_correlated_accounts_collapsed_onto_the_focus(ada: _Ada, db_session: Session):
    result = neighbor_subgraph(db_session, org_id=ada.org_id, start=ada.okta, depth=2, direction="out")

    assert result["truncated"] is False
    assert _labels(result["nodes"]) == {"Ada Lovelace", "Engineers", "repo-a", "Org Admin", "repo-b", "Deploy Bot"}
    start = result["nodes"][0]
    assert start["is_start"] is True
    assert start["id"] == ada.okta.id
    assert start["properties"]["cluster_size"] == 2
    assert start["properties"]["application_types"] == ["github", "okta"]
    assert {a["application_type"] for a in result["accounts"]} == {"okta", "github"}

    # The GitHub account's edges are rewritten onto the focused Okta node.
    edges = {(e["source_node_id"], e["target_node_id"]): e for e in result["edges"]}
    assert ada.github.id not in {nid for pair in edges for nid in pair}
    repo_b_edge = edges[(ada.okta.id, ada.repo_b.id)]
    assert repo_b_edge["properties"] == {"permission_level": "admin"}
    bot_edge = edges[(ada.okta.id, ada.bot.id)]
    assert bot_edge["access_path"] == "oauth_derived"
    assert bot_edge["properties"]["scopes"] == [
        {"name": "read:user", "is_sensitive": False},
        {"name": "repo", "is_sensitive": True},
    ]
    assert result["node_count"] == len(result["nodes"])
    assert result["edge_count"] == len(result["edges"]) == 5


def test_neighbor_node_type_filter_drops_nodes_and_the_edges_through_them(ada: _Ada, db_session: Session):
    result = neighbor_subgraph(
        db_session,
        org_id=ada.org_id,
        start=ada.okta,
        depth=2,
        direction="out",
        node_types=[GraphNodeType.RESOURCE],
    )

    # repo-a is reachable only through the filtered-out group, so no edge connects it.
    assert _labels(result["nodes"]) == {"Ada Lovelace", "repo-b"}
    assert [(e["source_node_id"], e["target_node_id"]) for e in result["edges"]] == [(ada.okta.id, ada.repo_b.id)]


def test_neighbor_access_path_filter_keeps_only_matching_edges(ada: _Ada, db_session: Session):
    result = neighbor_subgraph(
        db_session,
        org_id=ada.org_id,
        start=ada.okta,
        depth=2,
        direction="out",
        access_paths=[AccessPath.OAUTH_DERIVED, AccessPath.INHERITED_GROUP],
    )

    assert _labels(result["nodes"]) == {"Ada Lovelace", "Deploy Bot", "repo-a", "Engineers"}
    assert {e["access_path"] for e in result["edges"]} == {"oauth_derived", "inherited_group"}


def test_neighbors_of_a_non_identity_have_no_accounts(ada: _Ada, db_session: Session):
    result = neighbor_subgraph(db_session, org_id=ada.org_id, start=ada.repo_b, depth=1, direction="in")

    assert result["accounts"] is None
    assert _labels(result["nodes"]) == {"repo-b", "ada-octo"}
    assert "cluster_size" not in result["nodes"][0]["properties"]


def test_neighbor_depth_is_clamped_to_at_least_one(ada: _Ada, db_session: Session):
    result = neighbor_subgraph(db_session, org_id=ada.org_id, start=ada.group, depth=0, direction="out")

    assert result["depth"] == 1
    assert _labels(result["nodes"]) == {"Engineers", "repo-a"}


def test_neighbor_visit_cap_truncates_a_star_without_hitting_the_fetch_limit(db_session: Session):
    world = _World(db_session)
    group = world.node(GraphNodeType.GROUP, "Everyone")
    for index in range(150):
        member = world.node(GraphNodeType.GROUP, f"member-{index:03d}")
        world.edge(member, group, GraphEdgeType.MEMBER_OF)
    world.flush()

    result = neighbor_subgraph(db_session, org_id=world.org.id, start=group, depth=1, direction="in", max_nodes=10)

    assert result["truncated"] is True
    assert result["node_count"] == 10
    assert result["edge_count"] == 9


def test_reachability_returns_shortest_explained_paths_in_interest_order(ada: _Ada, db_session: Session):
    result = reachability_paths(db_session, org_id=ada.org_id, start=ada.okta, depth=3, direction="out")

    assert result["truncated"] is False
    assert result["total"] == result["returned"] == 5
    assert result["start"]["is_start"] is True
    assert result["start"]["properties"]["cluster_size"] == 2
    assert len(result["accounts"]) == 2
    # oauth app, role, resources (inherited_group outranks direct), then group.
    assert [p["destination"]["label"] for p in result["paths"]] == [
        "Deploy Bot",
        "Org Admin",
        "repo-a",
        "repo-b",
        "Engineers",
    ]

    by_dest = {p["destination"]["label"]: p for p in result["paths"]}
    repo_a = by_dest["repo-a"]
    assert repo_a["hop_count"] == 2
    assert repo_a["access_paths"] == ["direct", "inherited_group"]
    assert repo_a["primary_access_path"] == "inherited_group"
    assert [h["to"]["label"] for h in repo_a["hops"]] == ["Engineers", "repo-a"]
    assert all(h["explanation"] for h in repo_a["hops"])

    # A hop out of the sibling GitHub account starts at the focused node.
    repo_b_hop = by_dest["repo-b"]["hops"][0]
    assert repo_b_hop["from"]["id"] == ada.okta.id
    assert repo_b_hop["from"]["is_start"] is True
    assert repo_b_hop["properties"] == {"permission_level": "admin"}

    bot = by_dest["Deploy Bot"]
    assert bot["primary_access_path"] == "oauth_derived"
    assert [s["name"] for s in bot["hops"][0]["properties"]["scopes"]] == ["read:user", "repo"]

    assert result["summary"]["by_node_type"] == {
        "resource": 2,
        "group": 1,
        "oauth_application": 1,
        "role": 1,
    }
    assert result["summary"]["by_access_path"]["direct"] == 2


def test_reachability_filters_destination_types_and_caps_the_limit(ada: _Ada, db_session: Session):
    resources = reachability_paths(
        db_session,
        org_id=ada.org_id,
        start=ada.okta,
        direction="out",
        destination_types=[GraphNodeType.RESOURCE],
    )
    assert [p["destination"]["label"] for p in resources["paths"]] == ["repo-a", "repo-b"]

    capped = reachability_paths(db_session, org_id=ada.org_id, start=ada.okta, direction="out", limit=2)
    assert capped["total"] == 5
    assert capped["returned"] == 2
    assert capped["truncated"] is True
    assert sum(capped["summary"]["by_node_type"].values()) == 2


def test_reachability_inbound_answers_who_can_reach_a_resource(ada: _Ada, db_session: Session):
    result = reachability_paths(db_session, org_id=ada.org_id, start=ada.repo_a, depth=3, direction="in")

    assert result["accounts"] is None
    by_dest = {p["destination"]["label"]: p["hop_count"] for p in result["paths"]}
    assert by_dest == {"Engineers": 1, "Ada Lovelace": 2}


def test_reachability_rejects_bidirectional_walks(ada: _Ada, db_session: Session):
    with pytest.raises(ValueError, match="direction must be 'out' or 'in'"):
        reachability_paths(db_session, org_id=ada.org_id, start=ada.okta, direction="both")  # type: ignore[arg-type]


def test_search_collapses_a_correlated_person_onto_the_idp_account(ada: _Ada, db_session: Session):
    result = search_graph_nodes(db_session, org_id=ada.org_id, q="ada-octo")

    assert len(result["items"]) == 1
    item = result["items"][0]
    # Only the GitHub node matched, but the hit resolves to the Okta representative.
    assert item["id"] == ada.okta.id
    assert item["label"] == "Ada Lovelace"
    assert item["account_count"] == 2
    assert item["application_types"] == ["github", "okta"]
    assert item["detail_path"]
    assert item["graph_focus_path"]


def test_search_emits_one_item_per_person_and_plain_items_for_other_nodes(ada: _Ada, db_session: Session):
    ghost = ada.world.node(GraphNodeType.IDENTITY, "ada-ghost")  # a graph node with no identity row
    ada.world.flush()

    items = search_graph_nodes(db_session, org_id=ada.org_id, q="ada")["items"]

    identity_items = [i for i in items if i["node_type"] == "identity"]
    assert {i["id"] for i in identity_items} == {ada.okta.id, ghost.id}
    ghost_item = next(i for i in identity_items if i["id"] == ghost.id)
    assert ghost_item["account_count"] == 1
    assert ghost_item["application_types"] == []

    repos = search_graph_nodes(db_session, org_id=ada.org_id, q="repo", limit=1)["items"]
    assert len(repos) == 1
    assert "account_count" not in repos[0]


def test_node_lookups_are_scoped_to_the_org(ada: _Ada, db_session: Session):
    other = make_organization(db_session)

    assert get_org_node(db_session, org_id=ada.org_id, node_id=ada.repo_a.id) is ada.repo_a
    assert get_org_node(db_session, org_id=other.id, node_id=ada.repo_a.id) is None
    assert get_org_node(db_session, org_id=ada.org_id, node_id=uuid.uuid4()) is None
    assert resolve_node(db_session, org_id=ada.org_id, node_type="resource", object_id=ada.repo_a.object_id) is ada.repo_a
    assert (
        resolve_node(db_session, org_id=other.id, node_type=GraphNodeType.RESOURCE, object_id=ada.repo_a.object_id) is None
    )
