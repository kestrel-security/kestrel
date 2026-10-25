# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identities list filters and the graph Explore surface, beyond the auth/
tenant matrices.
"""

from __future__ import annotations

import uuid

import pytest
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

from tests.integration.test_api_factories import make_identity


def test_identities_filters_by_mfa_enabled(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    with_mfa = make_identity(db_session, org, mfa_enabled=True)
    without_mfa = make_identity(db_session, org, mfa_enabled=False)
    db_session.commit()

    response = client.get("/api/v1/identities", params={"mfa_enabled": "false"})

    assert response.status_code == 200
    ids = {row["id"] for row in response.json()["items"]}
    assert str(without_mfa.id) in ids
    assert str(with_mfa.id) not in ids


def test_identities_search_matches_email(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org, email="findme-unique@example.com")
    db_session.commit()

    response = client.get("/api/v1/identities", params={"search": "findme-unique"})

    assert response.status_code == 200
    ids = {row["id"] for row in response.json()["items"]}
    assert str(identity.id) in ids


def test_a_tombstoned_identity_is_hidden_from_the_list_and_detail(db_session):
    from datetime import UTC, datetime

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    live = make_identity(db_session, org, email="still-here@example.com")
    gone = make_identity(db_session, org, email="departed@example.com")
    gone.deleted_at = datetime.now(UTC)
    db_session.commit()

    listed = client.get("/api/v1/identities", params={"search": "example.com"})
    assert listed.status_code == 200
    ids = {row["id"] for row in listed.json()["items"]}
    assert str(live.id) in ids
    assert str(gone.id) not in ids

    assert client.get(f"/api/v1/identities/{gone.id}").status_code == 404
    assert client.get(f"/api/v1/identities/{gone.id}/access").status_code == 404
    assert client.get(f"/api/v1/identities/{live.id}").status_code == 200


def test_identities_rejects_an_unknown_identity_type(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/identities", params={"identity_type": "not-a-real-type"})

    assert response.status_code == 422


def test_get_identity_returns_the_row(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org)
    db_session.commit()

    response = client.get(f"/api/v1/identities/{identity.id}")

    assert response.status_code == 200
    assert response.json()["id"] == str(identity.id)


def _make_two_nodes_and_an_edge(session, org):
    source = GraphNode(
        id=uuid.uuid4(),
        org_id=org.id,
        node_type=GraphNodeType.IDENTITY,
        object_id=uuid.uuid4(),
        label="Source identity",
        properties={},
    )
    target = GraphNode(
        id=uuid.uuid4(),
        org_id=org.id,
        node_type=GraphNodeType.GROUP,
        object_id=uuid.uuid4(),
        label="Target group",
        properties={},
    )
    session.add_all([source, target])
    session.flush()
    edge = GraphEdge(
        id=uuid.uuid4(),
        org_id=org.id,
        source_node_id=source.id,
        target_node_id=target.id,
        edge_type=GraphEdgeType.MEMBER_OF,
        access_path=AccessPath.DIRECT,
    )
    session.add(edge)
    session.flush()
    return source, target, edge


def test_resolve_finds_a_node_by_type_and_object_id(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    source, _target, _edge = _make_two_nodes_and_an_edge(db_session, org)
    db_session.commit()

    response = client.get("/api/v1/graph/resolve", params={"node_type": "identity", "object_id": str(source.object_id)})

    assert response.status_code == 200
    assert response.json()["id"] == str(source.id)


def test_neighbors_returns_the_connected_node(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    source, target, _edge = _make_two_nodes_and_an_edge(db_session, org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/nodes/{source.id}/neighbors")

    assert response.status_code == 200
    body = response.json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert str(target.id) in node_ids


def test_edge_context_returns_both_endpoints(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    _source, _target, edge = _make_two_nodes_and_an_edge(db_session, org)
    db_session.commit()

    response = client.get(f"/api/v1/graph/edges/{edge.id}")

    assert response.status_code == 200


def test_resolve_unknown_node_type_is_422(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/graph/resolve", params={"node_type": "not-a-real-type", "object_id": str(uuid.uuid4())})

    assert response.status_code == 422


def test_resolve_missing_node_is_404(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/graph/resolve", params={"node_type": "identity", "object_id": str(uuid.uuid4())})

    assert response.status_code == 404


def test_identity_overview_composes_the_detail_page_payload(db_session):
    """One round trip carrying identity, cluster, access, findings, timeline."""
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org, email="grace@acme.test", display_name="Grace Hopper")
    db_session.commit()

    response = client.get(f"/api/v1/identities/{identity.id}/overview")

    assert response.status_code == 200
    body = response.json()
    assert body["identity"]["id"] == str(identity.id)
    assert set(body) >= {
        "identity",
        "application",
        "cluster",
        "groups",
        "grants",
        "oauth_grants",
        "access_preview",
        "findings",
        "risk_factors",
        "timeline",
        "explore_path",
    }
    assert body["cluster"]["member_count"] >= 1
    assert body["explore_path"].startswith("/explore?focus=")


def test_identity_overview_spans_the_correlated_accounts(db_session):
    """Access is shown for the person, not the single account being viewed."""
    from kestrel.identities.correlate import rebuild_identity_links

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    first = make_identity(db_session, org, email="shared@acme.test", display_name="Shared Person")
    second = make_identity(db_session, org, email="shared@acme.test", display_name="Shared Person")
    rebuild_identity_links(db_session, org_id=org.id)
    db_session.commit()

    body = client.get(f"/api/v1/identities/{first.id}/overview").json()

    assert body["cluster"]["member_count"] == 2
    assert {str(second.id), str(first.id)} == set(body["cluster"]["identity_ids"])


def test_identity_overview_labels_each_grant_with_its_own_application(db_session):
    """A grant held by another account in the person is labelled with that
    account's application, not the one being viewed."""
    from kestrel.db.models.access import Grant, GrantedVia, Permission, Role
    from kestrel.identities.correlate import rebuild_identity_links
    from kestrel.testing import make_application_instance

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    workspace = make_application_instance(db_session, org, display_name="Workspace")
    chat = make_application_instance(db_session, org, display_name="Chat")
    viewed = make_identity(db_session, org, application_instance=workspace, email="two-apps@acme.test")
    other = make_identity(db_session, org, application_instance=chat, email="two-apps@acme.test")
    provenance = {"source_connector_run_id": other.source_connector_run_id, "raw_source": {}}
    role = Role(
        id=uuid.uuid4(),
        org_id=org.id,
        application_instance_id=chat.id,
        provider_object_id="chat-admin",
        name="Chat Admin",
        is_privileged=True,
        **provenance,
    )
    # No role and no resource: only the holding account names the application.
    permission = Permission(
        id=uuid.uuid4(),
        org_id=org.id,
        application_instance_id=chat.id,
        provider_object_id="chat-export",
        name="Export",
        action="export",
        **provenance,
    )
    db_session.add_all([role, permission])
    db_session.flush()
    run_id = other.source_connector_run_id
    db_session.add_all(
        [
            Grant(
                org_id=org.id,
                identity_id=other.id,
                role_id=role.id,
                granted_via=GrantedVia.DIRECT,
                source_connector_run_id=run_id,
            ),
            Grant(
                org_id=org.id,
                identity_id=other.id,
                permission_id=permission.id,
                granted_via=GrantedVia.DIRECT,
                source_connector_run_id=run_id,
            ),
        ]
    )
    rebuild_identity_links(db_session, org_id=org.id)
    db_session.commit()

    body = client.get(f"/api/v1/identities/{viewed.id}/overview").json()

    assert body["cluster"]["member_count"] == 2
    labels = {(g["role_name"], g["application_instance_id"]) for g in body["grants"]}
    assert labels == {("Chat Admin", str(chat.id)), (None, str(chat.id))}


def test_identity_overview_is_404_for_a_tombstoned_identity(db_session):
    from datetime import UTC, datetime

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org)
    identity.deleted_at = datetime.now(UTC)
    db_session.commit()

    assert client.get(f"/api/v1/identities/{identity.id}/overview").status_code == 404


def test_identity_overview_lists_group_memberships(db_session):
    """Regression: the membership query selects two columns, so it must be
    executed rather than scalared -- the tuple unpack fails at runtime
    otherwise, and only an identity that actually has a group catches it."""
    import uuid as _uuid

    from kestrel.db.models.access import Group, GroupMembership

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org, email="member@acme.test", display_name="Group Member")
    group = Group(
        id=_uuid.uuid4(),
        org_id=org.id,
        application_instance_id=identity.application_instance_id,
        provider_object_id=f"grp-{_uuid.uuid4().hex[:8]}",
        name="Engineering",
        description="All engineers",
        source_connector_run_id=identity.source_connector_run_id,
        raw_source={},
    )
    db_session.add(group)
    db_session.flush()
    db_session.add(
        GroupMembership(
            id=_uuid.uuid4(),
            org_id=org.id,
            group_id=group.id,
            identity_id=identity.id,
            source_connector_run_id=identity.source_connector_run_id,
        )
    )
    db_session.commit()

    response = client.get(f"/api/v1/identities/{identity.id}/overview")

    assert response.status_code == 200
    groups = response.json()["groups"]
    assert [g["name"] for g in groups] == ["Engineering"]
    assert groups[0]["identity_id"] == str(identity.id)


def test_collapsed_identities_page_past_the_first_page(db_session):
    """collapse=true used to trim to the page before building it, so
    next_cursor was always null and people past the first page were unreachable."""
    from kestrel.db.models.application import ApplicationType
    from kestrel.identities.correlate import rebuild_identity_links
    from kestrel.testing import make_application, make_application_instance

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    instances = [
        make_application_instance(db_session, org, application=make_application(db_session, org, application_type=t))
        for t in (ApplicationType.OKTA, ApplicationType.GITHUB)
    ]
    people = 7
    for i in range(people):
        for instance in instances:
            make_identity(db_session, org, application_instance=instance, email=f"person{i}@acme.test")
    rebuild_identity_links(db_session, org_id=org.id)
    db_session.commit()

    params = {"collapse": "true", "limit": 3}
    body = client.get("/api/v1/identities", params=params).json()
    assert len(body["items"]) == 3
    assert body["next_cursor"] is not None

    emails: set[str] = set()
    for _ in range(10):  # hard stop so a broken cursor can't hang the test
        emails.update(item["email"] for item in body["items"])
        if body["next_cursor"] is None:
            break
        body = client.get("/api/v1/identities", params={**params, "cursor": body["next_cursor"]}).json()
    else:
        pytest.fail("did not reach a null next_cursor within 10 pages")
    # Pages cut on raw order, so a person whose accounts straddle a boundary
    # may show on both sides; nobody may be missed.
    assert emails == {f"person{i}@acme.test" for i in range(people)}
