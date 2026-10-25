# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Behavior the auth matrix can't express: the login credential exchange
itself, password-change validation, and session vs. API-token logout
semantics. Role gating for /auth/* is covered by test_api_auth_matrix.py.
"""

from __future__ import annotations

from kestrel.auth.service import create_api_token
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import DEFAULT_PASSWORD, api_client, make_operator, make_organization


def test_login_with_correct_credentials_returns_a_token(db_session):
    org = make_organization(db_session)
    operator = make_operator(db_session, org, email="login-test@example.com", password=DEFAULT_PASSWORD)
    db_session.commit()
    client = api_client(db_session, OperatorRole.ADMIN, org=org)

    response = client.post(
        "/api/v1/auth/login",
        json={"email": operator.email, "password": DEFAULT_PASSWORD},
        headers={"Authorization": ""},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token"]
    assert body["operator"]["email"] == operator.email


def test_login_with_wrong_password_is_rejected(db_session):
    org = make_organization(db_session)
    operator = make_operator(db_session, org, email="login-test-2@example.com", password=DEFAULT_PASSWORD)
    db_session.commit()
    client = api_client(db_session, OperatorRole.ADMIN, org=org)

    response = client.post(
        "/api/v1/auth/login",
        json={"email": operator.email, "password": "definitely-wrong"},
        headers={"Authorization": ""},
    )

    assert response.status_code == 401


def test_me_reflects_the_authenticated_operator(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == client.kestrel_operator.email
    assert body["role"] == "analyst"


def test_change_password_requires_the_correct_old_password(db_session):
    # api_client's own operator is created with DEFAULT_PASSWORD -- see
    # kestrel.testing.factories.make_operator.
    client = api_client(db_session)

    response = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "wrong-password", "new_password": "a-new-strong-password-123"},
    )

    # 400, not 401: the session is valid, and a client treats 401 as signed out.
    assert response.status_code == 400


def test_change_password_rejects_a_weak_new_password(db_session):
    client = api_client(db_session)

    response = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "correct-horse-battery-staple", "new_password": "short"},
    )

    assert response.status_code == 422


def test_logout_revokes_the_session_token(db_session):
    client = api_client(db_session)

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 204

    # The now-revoked token no longer authenticates.
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_logout_rejects_an_api_token_credential(db_session):
    """/auth/logout is for browser sessions; an API token isn't a session
    row to revoke -- callers use DELETE /api-tokens/{id} instead."""
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    _token_row, raw_token = create_api_token(db_session, operator, "cli token")
    db_session.commit()
    client = api_client(db_session, org=org)
    client.headers.update({"Authorization": f"Bearer {raw_token}"})

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 400


def test_login_refuses_oversized_credentials_before_hashing(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    oversized = [
        {"email": "a" * 309 + "@example.test", "password": DEFAULT_PASSWORD},  # 322 chars
        {"email": "someone@example.test", "password": "p" * 1025},
    ]

    for body in oversized:
        assert client.post("/api/v1/auth/login", json=body, headers={"Authorization": ""}).status_code == 422
