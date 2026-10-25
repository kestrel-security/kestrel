# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Ticket integration behavior beyond the auth/tenant matrices: config
validation per provider, token rotation, and that the API token is never
echoed back.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

from tests.integration.test_api_factories import make_ticket_integration


def test_create_github_issues_integration_requires_repo_config(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/ticket-integrations",
        json={
            "name": "GitHub Issues",
            "provider": "github_issues",
            "api_token": "ghp_test_token_0123456789",
            "config": {},
        },
    )

    assert response.status_code == 400


def test_create_github_issues_integration_never_echoes_the_token(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/ticket-integrations",
        json={
            "name": "GitHub Issues",
            "provider": "github_issues",
            "api_token": "ghp_test_token_0123456789",
            "config": {"repo": "kestrel-testing/example-repo"},
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert "api_token" not in body
    assert "ghp_test_token_0123456789" not in response.text


def test_create_rejects_an_unsupported_provider(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/ticket-integrations",
        json={"name": "Bogus", "provider": "not-a-real-provider", "api_token": "x" * 12},
    )

    assert response.status_code == 400


def test_rotate_token_succeeds_and_never_echoes_the_new_token(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    integration = make_ticket_integration(db_session, org)
    db_session.commit()

    response = client.post(
        f"/api/v1/ticket-integrations/{integration.id}/rotate-token",
        json={"api_token": "ghp_rotated_token_0123456789"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "id": str(integration.id)}
    assert "ghp_rotated_token_0123456789" not in response.text


def test_list_omits_the_token_for_every_row(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    make_ticket_integration(db_session, org)
    db_session.commit()

    response = client.get("/api/v1/ticket-integrations")

    assert response.status_code == 200
    assert len(response.json()) >= 1
    assert all("api_token" not in row and "secret" not in row for row in response.json())


def test_delete_removes_the_integration(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    integration = make_ticket_integration(db_session, org)
    db_session.commit()

    response = client.delete(f"/api/v1/ticket-integrations/{integration.id}")
    assert response.status_code == 204

    follow_up = client.get(f"/api/v1/ticket-integrations/{integration.id}")
    assert follow_up.status_code == 404
