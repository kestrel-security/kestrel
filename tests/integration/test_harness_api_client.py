# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.testing.api_client` produces a working authenticated client.

Everything in the API tier is built on this helper, so it gets its own check:
if the token wiring or the session override silently stopped working, dozens of
route tests would fail with an unhelpful 401 apiece.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_api_client_is_authenticated(db_session):
    client = api_client(db_session)

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["email"] == client.kestrel_operator.email


def test_api_client_honours_the_requested_role(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    assert client.get("/api/v1/auth/me").json()["role"] == "analyst"


def test_the_client_is_not_authenticated_without_its_token(db_session):
    client = api_client(db_session)

    response = client.get("/api/v1/auth/me", headers={"Authorization": ""})

    assert response.status_code == 401


def test_routes_see_the_tests_rolled_back_session(db_session):
    """The route handler must read through the caller's transaction: the
    operator `api_client` just created is only visible inside it."""
    client = api_client(db_session)
    assert client.get("/api/v1/auth/me").status_code == 200
    assert db_session.get_bind().in_transaction()


def test_each_client_gets_its_own_application(db_session):
    """No shared `app.dependency_overrides` (rule 4): two clients in one test
    must not be able to disturb each other."""
    first = api_client(db_session)
    second = api_client(db_session)

    assert first.app is not second.app
    assert first.get("/api/v1/auth/me").json()["email"] != second.get("/api/v1/auth/me").json()["email"]
