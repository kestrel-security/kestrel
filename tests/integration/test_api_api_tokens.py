# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""API token behavior beyond the auth matrix: the raw token is returned
once on create, ownership gates revoke for non-admins, and an admin can
list another operator's tokens.
"""

from __future__ import annotations

import pytest
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client, make_operator


def test_create_returns_the_raw_token_once(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.post("/api/v1/api-tokens", json={"name": "CLI token"})

    assert response.status_code == 201
    body = response.json()
    assert body["token"]
    assert body["token_prefix"]
    assert body["token"].startswith(body["token_prefix"])

    listed = client.get("/api/v1/api-tokens")
    assert listed.status_code == 200
    assert all("token" not in row for row in listed.json())


def test_operator_can_revoke_their_own_token(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    created = client.post("/api/v1/api-tokens", json={"name": "to revoke"})
    token_id = created.json()["id"]

    response = client.delete(f"/api/v1/api-tokens/{token_id}")

    assert response.status_code == 204


def test_operator_cannot_revoke_another_operators_token(db_session):
    owner_client = api_client(db_session, OperatorRole.READ_ONLY)
    org = owner_client.kestrel_org
    created = owner_client.post("/api/v1/api-tokens", json={"name": "owner's token"})
    token_id = created.json()["id"]

    other_client = api_client(db_session, OperatorRole.ANALYST, org=org)

    response = other_client.delete(f"/api/v1/api-tokens/{token_id}")

    assert response.status_code == 403


def test_admin_can_revoke_another_operators_token(db_session):
    owner_client = api_client(db_session, OperatorRole.READ_ONLY)
    org = owner_client.kestrel_org
    created = owner_client.post("/api/v1/api-tokens", json={"name": "owner's token"})
    token_id = created.json()["id"]

    admin_client = api_client(db_session, OperatorRole.ADMIN, org=org)

    response = admin_client.delete(f"/api/v1/api-tokens/{token_id}")

    assert response.status_code == 204


def test_listing_another_operators_tokens_requires_admin(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    other_operator = make_operator(db_session, org, role=OperatorRole.READ_ONLY)
    db_session.commit()

    response = client.get("/api/v1/api-tokens", params={"operator_id": str(other_operator.id)})

    assert response.status_code == 403


def _as(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_an_api_token_cannot_mint_another_api_token(db_session):
    # Without MFA too: a token must not be able to replace itself with a fresh one.
    client = api_client(db_session, OperatorRole.ANALYST)
    token = client.post("/api/v1/api-tokens", json={"name": "ci", "expires_in_days": 1}).json()["token"]

    response = client.post("/api/v1/api-tokens", json={"name": "copy"}, headers=_as(token))

    assert response.status_code == 403
    assert [row["name"] for row in client.get("/api/v1/api-tokens").json()] == ["ci"]


@pytest.mark.parametrize("days", [0, -1, 366, 10**9])
def test_token_lifetime_is_bounded(db_session, days):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/api-tokens", json={"name": "bounded", "expires_in_days": days})

    assert response.status_code == 422


def test_a_token_may_live_up_to_a_year(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/api-tokens", json={"name": "yearly", "expires_in_days": 365})

    assert response.status_code == 201
    (row,) = client.get("/api/v1/api-tokens").json()
    assert row["expires_at"] is not None
