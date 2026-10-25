# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator management behavior beyond the auth/tenant matrices: duplicate
email conflict, role/active toggling, and password reset clearing lockout
state.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_create_operator_rejects_a_duplicate_email(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    email = "dup-operator@example.com"

    first = client.post(
        "/api/v1/operators", json={"email": email, "role": "analyst", "password": "correct-horse-battery-staple"}
    )
    assert first.status_code == 201

    second = client.post(
        "/api/v1/operators", json={"email": email, "role": "analyst", "password": "correct-horse-battery-staple"}
    )
    assert second.status_code == 409


def test_create_operator_rejects_a_weak_password(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post("/api/v1/operators", json={"email": "weak@example.com", "role": "analyst", "password": "short"})

    assert response.status_code == 422


def test_create_operator_rejects_an_unknown_role(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/operators",
        json={"email": "badrole@example.com", "role": "superuser", "password": "correct-horse-battery-staple"},
    )

    assert response.status_code == 422


def test_patch_can_deactivate_an_operator(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    created = client.post(
        "/api/v1/operators",
        json={"email": "deactivate-me@example.com", "role": "read_only", "password": "correct-horse-battery-staple"},
    )
    operator_id = created.json()["id"]

    response = client.patch(f"/api/v1/operators/{operator_id}", json={"is_active": False})

    assert response.status_code == 200
    assert response.json()["is_active"] is False


def test_deactivation_revokes_sessions_and_tokens_for_good(db_session):
    # Reactivating must not bring back a credential issued before deactivation.
    admin = api_client(db_session, OperatorRole.ADMIN)
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)
    token = analyst.post("/api/v1/api-tokens", json={"name": "ci"}).json()["token"]
    operator_url = f"/api/v1/operators/{analyst.kestrel_operator.id}"
    assert analyst.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    assert admin.patch(operator_url, json={"is_active": False}).status_code == 200
    assert admin.patch(operator_url, json={"is_active": True}).status_code == 200

    assert analyst.get("/api/v1/auth/me").status_code == 401
    assert analyst.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_set_password_resets_lockout_state(db_session):
    from kestrel.db.models.operator import Operator

    client = api_client(db_session, OperatorRole.ADMIN)
    created = client.post(
        "/api/v1/operators",
        json={"email": "locked-out@example.com", "role": "read_only", "password": "correct-horse-battery-staple"},
    )
    operator_id = created.json()["id"]
    row = db_session.get(Operator, operator_id)
    row.failed_login_attempts = 5
    db_session.flush()

    response = client.post(
        f"/api/v1/operators/{operator_id}/set-password",
        json={"password": "a-brand-new-strong-password-1"},
    )

    assert response.status_code == 204
    db_session.refresh(row)
    assert row.failed_login_attempts == 0
    assert row.locked_until is None


def test_get_unknown_operator_is_404(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/operators/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
