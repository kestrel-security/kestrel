# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Ticket integration CRUD beyond create/rotate/delete basics: provider list,
read-back, patch semantics (name, description clear/keep, enable toggle,
config validation), not-found handling, token validation, and roles.
"""

from __future__ import annotations

import uuid

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.ticket import TicketIntegration
from kestrel.testing import api_client
from sqlalchemy import select

from tests.integration.test_api_factories import make_ticket_integration


def test_providers_lists_the_builtin_github_provider(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.get("/api/v1/ticket-integrations/providers")

    assert response.status_code == 200
    assert "github_issues" in response.text


def test_create_then_read_back_then_list(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    created = client.post(
        "/api/v1/ticket-integrations",
        json={
            "name": "Issues",
            "provider": "github_issues",
            "api_token": "ghp_0123456789abcdef",
            "config": {"repo": "acme/security"},
            "description": "triage queue",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]

    detail = client.get(f"/api/v1/ticket-integrations/{integration_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["name"] == "Issues"
    assert body["config"]["repo"] == "acme/security"
    assert body["description"] == "triage queue"
    assert body["is_enabled"] is True
    assert "ghp_0123456789abcdef" not in detail.text

    assert [r["id"] for r in client.get("/api/v1/ticket-integrations").json()] == [integration_id]


def test_create_rejects_a_short_token(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/ticket-integrations",
        json={"name": "Issues", "provider": "github_issues", "api_token": "short", "config": {"repo": "a/b"}},
    )

    assert response.status_code == 400


def test_patch_updates_name_disables_and_keeps_description(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, client.kestrel_org, description="keep me")
    db_session.commit()

    response = client.patch(f"/api/v1/ticket-integrations/{row.id}", json={"name": "Renamed", "is_enabled": False})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "Renamed"
    assert body["is_enabled"] is False
    assert body["description"] == "keep me"
    audit = db_session.scalars(
        select(AuditLog).where(AuditLog.org_id == client.kestrel_org.id, AuditLog.action == "ticket_integration.updated")
    ).one()
    assert sorted(audit.context["fields"]) == ["is_enabled", "name"]
    assert audit.context["token_rotated"] is False


def test_patch_can_clear_the_description(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, client.kestrel_org, description="old")
    db_session.commit()

    response = client.patch(f"/api/v1/ticket-integrations/{row.id}", json={"description": None, "description_set": True})

    assert response.status_code == 200
    assert response.json()["description"] is None


def test_patch_changes_the_repo(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, client.kestrel_org)
    db_session.commit()

    response = client.patch(f"/api/v1/ticket-integrations/{row.id}", json={"config": {"repo": "acme/other"}})

    assert response.status_code == 200
    assert response.json()["config"]["repo"] == "acme/other"


def test_patch_rejects_invalid_config_and_name(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, client.kestrel_org)
    db_session.commit()

    assert client.patch(f"/api/v1/ticket-integrations/{row.id}", json={"config": {}}).status_code == 400
    assert client.patch(f"/api/v1/ticket-integrations/{row.id}", json={"name": "   "}).status_code == 400


def test_rotate_token_rejects_a_short_token_and_keeps_the_old_one(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, client.kestrel_org)
    db_session.commit()
    before = bytes(row.secret_ciphertext)

    response = client.post(f"/api/v1/ticket-integrations/{row.id}/rotate-token", json={"api_token": "tiny"})

    assert response.status_code == 400
    db_session.expire_all()
    assert bytes(db_session.get(TicketIntegration, row.id).secret_ciphertext) == before


def test_routes_are_404_for_unknown_or_foreign_integrations(db_session):
    owner = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, owner.kestrel_org)
    db_session.commit()
    other = api_client(db_session, OperatorRole.ADMIN)

    for integration_id in (row.id, uuid.uuid4()):
        base = f"/api/v1/ticket-integrations/{integration_id}"
        assert other.get(base).status_code == 404
        assert other.patch(base, json={"name": "x"}).status_code == 404
        assert other.post(f"{base}/rotate-token", json={"api_token": "long-enough-token"}).status_code == 404
        assert other.delete(base).status_code == 404
    assert other.get("/api/v1/ticket-integrations").json() == []


def test_analyst_can_list_but_not_manage(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    row = make_ticket_integration(db_session, admin.kestrel_org)
    db_session.commit()
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)

    assert analyst.get("/api/v1/ticket-integrations").status_code == 200
    assert analyst.get(f"/api/v1/ticket-integrations/{row.id}").status_code == 403
    assert analyst.patch(f"/api/v1/ticket-integrations/{row.id}", json={"name": "x"}).status_code == 403
    assert analyst.delete(f"/api/v1/ticket-integrations/{row.id}").status_code == 403
