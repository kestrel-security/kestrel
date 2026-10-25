# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Session revocation on password change/reset, login timing uniformity, the
atomic failed-attempt counter, and the per-email login bucket.

Regressions for the security review's findings 4, 5, 7 and 8.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.auth import service as auth_service
from kestrel.auth.service import (
    LOCKOUT_THRESHOLD,
    authenticate_operator,
    create_api_token,
    create_session,
    lookup_operator_by_bearer_token,
)
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.rate_limit.config import RateLimitSettings
from kestrel.rate_limit.store import MemoryRateLimitStore
from kestrel.testing import DEFAULT_PASSWORD, api_client, make_operator, make_organization
from kestrel_api.middleware import rate_limit as rl
from sqlalchemy import update

NEW_PASSWORD = "a-brand-new-long-password"


# -- finding 5: sessions and tokens do not outlive a password change -------------


def test_change_password_revokes_other_sessions_but_keeps_the_current_one(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    operator = client.kestrel_operator
    _other_row, other_token = create_session(db_session, operator)
    _api_row, api_token = create_api_token(db_session, operator, "ci")
    db_session.flush()

    response = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DEFAULT_PASSWORD, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 204, response.text
    assert lookup_operator_by_bearer_token(db_session, other_token) is None
    assert lookup_operator_by_bearer_token(db_session, client.kestrel_token) is not None
    # API tokens are deliberate, named credentials: left alone here.
    assert lookup_operator_by_bearer_token(db_session, api_token) is not None
    assert client.get("/api/v1/auth/me").status_code == 200


def test_admin_set_password_revokes_all_sessions_and_api_tokens(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    target = make_operator(db_session, admin.kestrel_org, role=OperatorRole.ANALYST)
    _row, session_token = create_session(db_session, target)
    _api_row, api_token = create_api_token(db_session, target, "laptop")
    db_session.flush()

    response = admin.post(f"/api/v1/operators/{target.id}/set-password", json={"password": NEW_PASSWORD})

    assert response.status_code == 204, response.text
    assert lookup_operator_by_bearer_token(db_session, session_token) is None
    assert lookup_operator_by_bearer_token(db_session, api_token) is None


def test_admin_set_password_can_keep_api_tokens(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    target = make_operator(db_session, admin.kestrel_org, role=OperatorRole.ANALYST)
    _row, session_token = create_session(db_session, target)
    _api_row, api_token = create_api_token(db_session, target, "automation")
    db_session.flush()

    response = admin.post(
        f"/api/v1/operators/{target.id}/set-password",
        json={"password": NEW_PASSWORD, "revoke_api_tokens": False},
    )

    assert response.status_code == 204, response.text
    assert lookup_operator_by_bearer_token(db_session, session_token) is None
    assert lookup_operator_by_bearer_token(db_session, api_token) is not None


def test_admin_resetting_their_own_password_keeps_their_session(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)

    response = admin.post(f"/api/v1/operators/{admin.kestrel_operator.id}/set-password", json={"password": NEW_PASSWORD})

    assert response.status_code == 204, response.text
    assert admin.get("/api/v1/auth/me").status_code == 200


# -- finding 7: every failure path pays for one Argon2 verification ---------------


@pytest.fixture
def burn_calls(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(auth_service, "burn_password_check", lambda raw: calls.append(raw))
    return calls


def test_unknown_email_runs_a_dummy_verification(db_session, burn_calls):
    org = make_organization(db_session)

    assert authenticate_operator(db_session, org.id, "nobody@example.com", "guess-guess-guess") is None
    assert burn_calls == ["guess-guess-guess"]


def test_inactive_account_runs_a_dummy_verification(db_session, burn_calls):
    org = make_organization(db_session)
    operator = make_operator(db_session, org, is_active=False)

    assert authenticate_operator(db_session, org.id, operator.email, DEFAULT_PASSWORD) is None
    assert len(burn_calls) == 1


def test_locked_account_runs_a_dummy_verification(db_session, burn_calls):
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    operator.locked_until = datetime(2999, 1, 1, tzinfo=UTC)
    db_session.flush()

    assert authenticate_operator(db_session, org.id, operator.email, DEFAULT_PASSWORD) is None
    assert len(burn_calls) == 1


# -- finding 8: the failed-attempt counter is incremented in SQL -------------------


def test_failed_attempts_count_from_the_database_not_a_stale_object(db_session):
    """Simulates the race: another request has already recorded attempts the
    loaded object does not know about. A Python-side `+= 1` would write 1;
    the atomic UPDATE sees the real count and locks the account."""
    org = make_organization(db_session)
    operator = make_operator(db_session, org)
    assert operator.failed_login_attempts == 0
    db_session.execute(
        update(Operator)
        .where(Operator.id == operator.id)
        .values(failed_login_attempts=LOCKOUT_THRESHOLD - 1)
        .execution_options(synchronize_session=False)
    )
    assert operator.failed_login_attempts == 0  # the in-memory copy is stale

    assert authenticate_operator(db_session, org.id, operator.email, "wrong-password-here") is None

    db_session.refresh(operator)
    assert operator.failed_login_attempts == LOCKOUT_THRESHOLD
    assert operator.locked_until is not None


# -- finding 4: a per-email login bucket alongside the per-IP one ------------------


@pytest.fixture
def login_limits(monkeypatch):
    runtime = rl.RateLimitRuntime(
        settings=RateLimitSettings(enabled=True, login_limit=3, backend="memory"),
        store=MemoryRateLimitStore(),
    )
    monkeypatch.setattr(rl, "runtime", runtime)
    return runtime


def test_login_is_throttled_per_email(db_session, login_limits):
    org = make_organization(db_session)
    operator = make_operator(db_session, org, email="target@example.com")
    client = api_client(db_session, OperatorRole.ADMIN, org=org)
    # Earlier attempts against this account from elsewhere already used the
    # account's budget (the middleware's IP bucket here is still empty).
    for _ in range(3):
        rl.check_login_email_limit("TARGET@example.com", rt=login_limits)

    response = client.post(
        "/api/v1/auth/login",
        json={"email": operator.email, "password": DEFAULT_PASSWORD},
        headers={"Authorization": ""},
    )

    assert response.status_code == 429
    assert "this account" in response.json()["detail"]
    assert "Retry-After" in response.headers


def test_login_records_the_forwarded_client_ip(db_session, monkeypatch):
    from fastapi.testclient import TestClient
    from kestrel.db.models.operator import OperatorSession
    from sqlalchemy import select

    monkeypatch.setenv("KESTREL_TRUSTED_PROXIES", "172.16.0.0/12")
    org = make_organization(db_session)
    operator = make_operator(db_session, org, email="ip-test@example.com")
    # Same app, but the TCP peer is the (trusted) web container.
    client = TestClient(api_client(db_session, OperatorRole.ADMIN, org=org).app, client=("172.18.0.3", 5000))

    response = client.post(
        "/api/v1/auth/login",
        json={"email": operator.email, "password": DEFAULT_PASSWORD},
        headers={"Authorization": "", "X-Forwarded-For": "198.51.100.23"},
    )

    assert response.status_code == 200, response.text
    row = db_session.scalars(select(OperatorSession).where(OperatorSession.operator_id == operator.id)).one()
    assert row.ip_address == "198.51.100.23"
