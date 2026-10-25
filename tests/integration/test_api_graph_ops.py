# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Graph Explore routes (search, paths, neighbors filters, edge context,
node context) and the identity access / list filters, over a small
hand-built graph:

    identity --member_of--> group --assigned_role--> role --can_access--> resource
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client, make_application_instance

from tests.integration.test_api_factories import make_identity


@dataclass
class Chain:
    identity: GraphNode
    group: GraphNode
    role: GraphNode
    resource: GraphNode
    edges: list[GraphEdge]


def _node(session, org, node_type: GraphNodeType, label: str, object_id: uuid.UUID | None = None) -> GraphNode:
    node = GraphNode(
        id=uuid.uuid4(),
        org_id=org.id,
        node_type=node_type,
        object_id=object_id or uuid.uuid4(),
        label=label,
        properties={},
    )
    session.add(node)
    session.flush()
    return node


def _edge(session, org, src: GraphNode, tgt: GraphNode, edge_type: GraphEdgeType, access: AccessPath) -> GraphEdge:
    edge = GraphEdge(
        id=uuid.uuid4(),
        org_id=org.id,
        source_node_id=src.id,
        target_node_id=tgt.id,
        edge_type=edge_type,
        access_path=access,
    )
    session.add(edge)
    session.flush()
    return edge


def _chain(session, org, *, identity_object_id: uuid.UUID | None = None, tag: str | None = None) -> Chain:
    tag = tag or uuid.uuid4().hex[:6]
    identity = _node(session, org, GraphNodeType.IDENTITY, f"Ada {tag}", identity_object_id)
    group = _node(session, org, GraphNodeType.GROUP, f"Engineers {tag}")
    role = _node(session, org, GraphNodeType.ROLE, f"Admin role {tag}")
    resource = _node(session, org, GraphNodeType.RESOURCE, f"Prod repo {tag}")
    edges = [
        _edge(session, org, identity, group, GraphEdgeType.MEMBER_OF, AccessPath.DIRECT),
        _edge(session, org, group, role, GraphEdgeType.ASSIGNED_ROLE, AccessPath.INHERITED_GROUP),
        _edge(session, org, role, resource, GraphEdgeType.CAN_ACCESS, AccessPath.INHERITED_ROLE),
    ]
    return Chain(identity, group, role, resource, edges)


# --- paths ----------------------------------------------------------------


def test_paths_out_reach_every_downstream_node_with_hops(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/nodes/{chain.identity.id}/paths")

    assert response.status_code == 200
    body = response.json()
    assert body["direction"] == "out"
    assert body["total"] == 3
    assert body["truncated"] is False
    by_dest = {p["destination"]["id"]: p for p in body["paths"]}
    assert set(by_dest) == {str(chain.group.id), str(chain.role.id), str(chain.resource.id)}
    to_resource = by_dest[str(chain.resource.id)]
    assert to_resource["hop_count"] == 3
    assert [h["edge_type"] for h in to_resource["hops"]] == ["member_of", "assigned_role", "can_access"]
    assert to_resource["hops"][0]["from"]["id"] == str(chain.identity.id)
    assert to_resource["access_paths"] == ["direct", "inherited_group", "inherited_role"]
    # Roles sort before resources, which sort before groups.
    assert [p["destination"]["node_type"] for p in body["paths"]] == ["role", "resource", "group"]
    assert body["summary"]["by_node_type"] == {"group": 1, "resource": 1, "role": 1}


def test_paths_respect_depth_destination_types_and_limit(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()
    url = f"/api/v1/graph/nodes/{chain.identity.id}/paths"

    shallow = client.get(url, params={"depth": 1}).json()
    assert [p["destination"]["id"] for p in shallow["paths"]] == [str(chain.group.id)]

    only_resources = client.get(url, params={"destination_types": "resource"}).json()
    assert [p["destination"]["id"] for p in only_resources["paths"]] == [str(chain.resource.id)]

    limited = client.get(url, params={"limit": 1}).json()
    assert limited["returned"] == 1
    assert limited["total"] == 3
    assert limited["truncated"] is True


def test_paths_in_answer_who_reaches_a_node(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    body = client.get(f"/api/v1/graph/nodes/{chain.resource.id}/paths", params={"direction": "in"}).json()

    assert {p["destination"]["id"] for p in body["paths"]} == {
        str(chain.role.id),
        str(chain.group.id),
        str(chain.identity.id),
    }


@pytest.mark.parametrize(
    "params",
    [{"direction": "both"}, {"destination_types": "identity,spaceship"}, {"depth": 0}],
    ids=["bad-direction", "bad-type", "bad-depth"],
)
def test_paths_reject_invalid_parameters(db_session, params):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/nodes/{chain.identity.id}/paths", params=params)

    assert response.status_code == 422


def test_graph_node_routes_are_404_for_another_orgs_node(db_session):
    owner = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, owner.kestrel_org)
    db_session.commit()
    other = api_client(db_session, OperatorRole.READ_ONLY)

    for suffix in ("paths", "neighbors", "context"):
        assert other.get(f"/api/v1/graph/nodes/{chain.identity.id}/{suffix}").status_code == 404
        assert other.get(f"/api/v1/graph/nodes/{uuid.uuid4()}/{suffix}").status_code == 404
    assert other.get(f"/api/v1/graph/edges/{chain.edges[0].id}").status_code == 404
    assert other.get(f"/api/v1/graph/edges/{uuid.uuid4()}").status_code == 404


# --- neighbors ------------------------------------------------------------


def test_neighbors_filter_by_node_type_and_access_path(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()
    url = f"/api/v1/graph/nodes/{chain.identity.id}/neighbors"

    everything = client.get(url).json()
    assert everything["node_count"] == 4
    assert everything["edge_count"] == 3
    assert everything["truncated"] is False

    shallow = client.get(url, params={"depth": 1}).json()
    assert {n["id"] for n in shallow["nodes"]} == {str(chain.identity.id), str(chain.group.id)}

    direct_only = client.get(url, params={"access_paths": "direct"}).json()
    assert {e["access_path"] for e in direct_only["edges"]} == {"direct"}

    reverse = client.get(f"/api/v1/graph/nodes/{chain.resource.id}/neighbors", params={"direction": "in"}).json()
    assert str(chain.identity.id) in {n["id"] for n in reverse["nodes"]}


@pytest.mark.parametrize("params", [{"node_types": "planet"}, {"access_paths": "telepathy"}])
def test_neighbors_reject_unknown_filters(db_session, params):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/nodes/{chain.identity.id}/neighbors", params=params)

    assert response.status_code == 422


def test_neighbors_blank_filters_mean_no_filter(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(
        f"/api/v1/graph/nodes/{chain.identity.id}/neighbors", params={"node_types": " , ", "access_paths": " "}
    )

    assert response.status_code == 200
    assert response.json()["node_count"] == 4


# --- search ---------------------------------------------------------------


def test_search_matches_labels_and_filters_by_type(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    tag = uuid.uuid4().hex[:6]
    chain = _chain(db_session, client.kestrel_org, tag=tag)
    db_session.commit()

    everything = client.get("/api/v1/graph/search", params={"q": tag}).json()["items"]
    assert {i["id"] for i in everything} == {
        str(chain.identity.id),
        str(chain.group.id),
        str(chain.role.id),
        str(chain.resource.id),
    }
    for item in everything:
        assert item["graph_focus_path"]

    groups = client.get("/api/v1/graph/search", params={"q": tag, "node_types": "group,role"}).json()["items"]
    assert {i["node_type"] for i in groups} == {"group", "role"}

    limited = client.get("/api/v1/graph/search", params={"q": tag, "limit": 1}).json()["items"]
    assert len(limited) == 1


def test_search_is_scoped_to_the_org_and_validates_input(db_session):
    owner = api_client(db_session, OperatorRole.READ_ONLY)
    tag = uuid.uuid4().hex[:6]
    _chain(db_session, owner.kestrel_org, tag=tag)
    db_session.commit()
    other = api_client(db_session, OperatorRole.READ_ONLY)

    assert other.get("/api/v1/graph/search", params={"q": tag}).json()["items"] == []
    assert other.get("/api/v1/graph/search", params={"q": ""}).status_code == 422
    assert other.get("/api/v1/graph/search", params={"q": tag, "node_types": "nope"}).status_code == 422
    assert other.get("/api/v1/graph/search", params={"q": tag, "limit": 51}).status_code == 422


# --- edges and node context -----------------------------------------------


def test_edge_context_describes_both_endpoints(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/edges/{chain.edges[1].id}")

    assert response.status_code == 200
    body = response.json()
    assert body["edge"]["id"] == str(chain.edges[1].id)
    assert str(chain.group.id) in response.text
    assert str(chain.role.id) in response.text


def test_node_context_returns_for_an_org_node(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    chain = _chain(db_session, client.kestrel_org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/nodes/{chain.group.id}/context")

    assert response.status_code == 200
    assert str(chain.group.id) in response.text


# --- identities access + list filters --------------------------------------


def test_identity_access_flattens_reachable_nodes_by_type(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org)
    chain = _chain(db_session, org, identity_object_id=identity.id)
    db_session.commit()

    response = client.get(f"/api/v1/identities/{identity.id}/access")

    assert response.status_code == 200
    body = response.json()
    assert body["depth"] == 3
    assert body["total"] == 3
    assert str(chain.resource.id) in response.text

    shallow = client.get(f"/api/v1/identities/{identity.id}/access", params={"depth": 1}).json()
    assert shallow["total"] == 1


def test_identity_access_without_a_graph_node_is_empty(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    identity = make_identity(db_session, client.kestrel_org)
    db_session.commit()

    body = client.get(f"/api/v1/identities/{identity.id}/access").json()

    assert body == {"depth": 3, "total": 0, "reachable": [], "groups": []}


def test_identity_access_is_404_for_unknown_or_foreign_identity(db_session):
    owner = api_client(db_session, OperatorRole.READ_ONLY)
    identity = make_identity(db_session, owner.kestrel_org)
    db_session.commit()
    other = api_client(db_session, OperatorRole.READ_ONLY)

    assert other.get(f"/api/v1/identities/{identity.id}/access").status_code == 404
    assert other.get(f"/api/v1/identities/{uuid.uuid4()}/access").status_code == 404
    assert other.get(f"/api/v1/identities/{identity.id}/overview").status_code == 404
    assert owner.get(f"/api/v1/identities/{identity.id}/access", params={"depth": 7}).status_code == 422


def test_identities_filter_by_type_external_and_application_instance(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    app_a = make_application_instance(db_session, org)
    app_b = make_application_instance(db_session, org)
    internal = make_identity(db_session, org, application_instance=app_a, display_name="Inside Person")
    external = make_identity(db_session, org, application_instance=app_b, is_external=True, display_name="Outside Person")
    db_session.commit()

    def ids(**params) -> set[str]:
        response = client.get("/api/v1/identities", params=params)
        assert response.status_code == 200
        return {row["id"] for row in response.json()["items"]}

    assert ids(identity_type="user") == {str(internal.id), str(external.id)}
    assert ids(is_external="true") == {str(external.id)}
    assert ids(application_instance_id=str(app_a.id)) == {str(internal.id)}
    assert ids(privileged="false") == {str(internal.id), str(external.id)}
    assert ids(privileged="true") == set()
    assert ids(collapse="true") == {str(internal.id), str(external.id)}
