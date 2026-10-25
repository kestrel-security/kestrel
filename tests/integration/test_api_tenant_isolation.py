# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""One tenant-isolation contract, parametrized over every org-scoped
resource that has an id-addressed HTTP route.

There is no Postgres RLS backstop (ADR-0006) -- `WHERE org_id = ...` on every
query is the only thing standing between org A and org B's rows. This file
is the regression test for that promise: org B's operator, at whatever role
the resource normally requires, must get a plain 404 for org A's row --
never a 200, never a 403 that would at least confirm the row exists, and
never org A's row showing up in org B's list.

Each `Probe` builds one row in a fresh org (via `kestrel.testing` factories
or the `test_api_factories` helpers -- never a connector sync, never a demo
persona) and declares which routes to check it against. Adding a new
org-scoped resource means adding one `Probe`, not a new test function.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from kestrel.auth.service import create_api_token
from kestrel.dashboard import boards as boards_svc
from kestrel.db.models.graph_edge import GraphNode, GraphNodeType
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.org import Organization
from kestrel.testing import api_client, make_connector_instance, make_operator, make_organization
from sqlalchemy.orm import Session

from tests.integration.test_api_factories import (
    make_finding,
    make_identity,
    make_policy,
    make_ticket_integration,
    make_webhook,
)


def _items_bare_list(body: Any) -> list[dict]:
    return list(body)


def _items_key(key: str) -> Callable[[Any], list[dict]]:
    return lambda body: list(body[key])


@dataclass
class Probe:
    name: str
    role: OperatorRole
    make: Callable[[Session, Organization], str]
    get_path: str | None = None
    list_path: str | None = None
    list_items: Callable[[Any], list[dict]] = _items_bare_list
    patch_path: str | None = None
    patch_body: dict | None = None
    delete_path: str | None = None


def _make_connector_instance_row(session: Session, org: Organization) -> str:
    return str(make_connector_instance(session, org).id)


def _make_operator_row(session: Session, org: Organization) -> str:
    return str(make_operator(session, org, role=OperatorRole.READ_ONLY).id)


def _make_identity_row(session: Session, org: Organization) -> str:
    return str(make_identity(session, org).id)


def _make_policy_row(session: Session, org: Organization) -> str:
    return str(make_policy(session, org).id)


def _make_finding_row(session: Session, org: Organization) -> str:
    return str(make_finding(session, org).id)


def _make_webhook_row(session: Session, org: Organization) -> str:
    endpoint, _secret = make_webhook(session, org)
    return str(endpoint.id)


def _make_ticket_integration_row(session: Session, org: Organization) -> str:
    return str(make_ticket_integration(session, org).id)


def _make_dashboard_row(session: Session, org: Organization) -> str:
    admin = make_operator(session, org, role=OperatorRole.ADMIN)
    created = boards_svc.create_dashboard(
        session, org_id=org.id, operator=admin, name=f"Isolation probe {uuid.uuid4().hex[:6]}"
    )
    return str(created["id"])


def _make_graph_node_row(session: Session, org: Organization) -> str:
    node = GraphNode(
        id=uuid.uuid4(),
        org_id=org.id,
        node_type=GraphNodeType.IDENTITY,
        object_id=uuid.uuid4(),
        label="Isolation probe node",
        properties={},
    )
    session.add(node)
    session.flush()
    return str(node.id)


def _make_api_token_row(session: Session, org: Organization) -> str:
    owner = make_operator(session, org, role=OperatorRole.READ_ONLY)
    token_row, _raw = create_api_token(session, owner, "isolation probe token")
    return str(token_row.id)


PROBES: list[Probe] = [
    Probe(
        "connector_instance",
        OperatorRole.ANALYST,
        _make_connector_instance_row,
        get_path="/api/v1/connector-instances/{id}",
        list_path="/api/v1/connector-instances",
        patch_path="/api/v1/connector-instances/{id}",
        patch_body={"config": {}},
        delete_path="/api/v1/connector-instances/{id}",
    ),
    Probe(
        "operator",
        OperatorRole.ADMIN,
        _make_operator_row,
        get_path="/api/v1/operators/{id}",
        list_path="/api/v1/operators",
        patch_path="/api/v1/operators/{id}",
        patch_body={"display_name": "Changed by org B"},
    ),
    Probe(
        "identity",
        OperatorRole.READ_ONLY,
        _make_identity_row,
        get_path="/api/v1/identities/{id}",
        list_path="/api/v1/identities",
        list_items=_items_key("items"),
    ),
    Probe(
        "policy",
        OperatorRole.ANALYST,
        _make_policy_row,
        get_path="/api/v1/policies/{id}",
        list_path="/api/v1/policies",
        patch_path="/api/v1/policies/{id}",
        patch_body={"is_enabled": False},
        delete_path="/api/v1/policies/{id}",
    ),
    Probe(
        "finding",
        OperatorRole.ANALYST,
        _make_finding_row,
        get_path="/api/v1/findings/{id}",
        list_path="/api/v1/findings",
        list_items=_items_key("items"),
        patch_path="/api/v1/findings/{id}",
        patch_body={"status": "resolved"},
    ),
    Probe(
        "webhook",
        OperatorRole.ADMIN,
        _make_webhook_row,
        get_path="/api/v1/webhooks/{id}",
        list_path="/api/v1/webhooks",
        patch_path="/api/v1/webhooks/{id}",
        patch_body={"is_enabled": False},
        delete_path="/api/v1/webhooks/{id}",
    ),
    Probe(
        "ticket_integration",
        OperatorRole.ADMIN,
        _make_ticket_integration_row,
        get_path="/api/v1/ticket-integrations/{id}",
        list_path="/api/v1/ticket-integrations",
        patch_path="/api/v1/ticket-integrations/{id}",
        patch_body={"name": "Changed by org B"},
        delete_path="/api/v1/ticket-integrations/{id}",
    ),
    Probe(
        "dashboard",
        OperatorRole.READ_ONLY,
        _make_dashboard_row,
        get_path="/api/v1/dashboards/{id}",
        list_path="/api/v1/dashboards",
        list_items=_items_key("dashboards"),
    ),
    Probe(
        "graph_node",
        OperatorRole.READ_ONLY,
        _make_graph_node_row,
        get_path="/api/v1/graph/nodes/{id}/context",
    ),
    Probe(
        "api_token",
        OperatorRole.READ_ONLY,
        _make_api_token_row,
        delete_path="/api/v1/api-tokens/{id}",
    ),
]


def _ids() -> list[str]:
    return [p.name for p in PROBES]


@pytest.mark.parametrize("probe", PROBES, ids=_ids())
def test_cross_org_read_is_a_404(db_session, probe: Probe):
    org_a = make_organization(db_session)
    row_id = probe.make(db_session, org_a)

    org_b = make_organization(db_session)
    client = api_client(db_session, probe.role, org=org_b)

    if probe.get_path is not None:
        response = client.get(probe.get_path.format(id=row_id))
        assert response.status_code == 404, f"org B read org A's {probe.name} ({response.status_code})"


@pytest.mark.parametrize("probe", PROBES, ids=_ids())
def test_cross_org_row_never_enumerated(db_session, probe: Probe):
    org_a = make_organization(db_session)
    row_id = probe.make(db_session, org_a)

    org_b = make_organization(db_session)
    client = api_client(db_session, probe.role, org=org_b)

    if probe.list_path is not None:
        response = client.get(probe.list_path)
        assert response.status_code == 200
        items = probe.list_items(response.json())
        assert row_id not in {str(item["id"]) for item in items}, f"org A's {probe.name} leaked into org B's list"


@pytest.mark.parametrize("probe", PROBES, ids=_ids())
def test_cross_org_mutation_is_a_404(db_session, probe: Probe):
    org_a = make_organization(db_session)
    row_id = probe.make(db_session, org_a)

    org_b = make_organization(db_session)
    client = api_client(db_session, probe.role, org=org_b)

    if probe.patch_path is not None:
        response = client.patch(probe.patch_path.format(id=row_id), json=probe.patch_body or {})
        assert response.status_code == 404, f"org B patched org A's {probe.name} ({response.status_code})"

    if probe.delete_path is not None:
        response = client.delete(probe.delete_path.format(id=row_id))
        assert response.status_code == 404, f"org B deleted org A's {probe.name} ({response.status_code})"
