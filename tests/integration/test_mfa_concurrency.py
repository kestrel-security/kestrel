# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Second-factor and challenge consumption must survive overlapping API calls."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from kestrel.auth import mfa
from kestrel.auth.service import create_session
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import MFA_STATE_CHALLENGE, MFA_STATE_VERIFIED, Operator, OperatorSession
from kestrel.db.models.org import Organization
from kestrel.testing import make_operator, make_organization
from kestrel_api import deps
from kestrel_api.main import create_app
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session


@pytest.fixture
def enrolled_operator(db_engine):
    now = datetime.now(UTC)
    with Session(db_engine) as setup:
        org = make_organization(setup)
        operator = make_operator(setup, org)
        operator_id = operator.id
        secret, _uri = mfa.start_enrolment(operator)
        previous = now - timedelta(seconds=mfa.STEP_SECONDS)
        recovery_codes = mfa.activate(setup, operator, mfa.totp(secret, previous), now=previous)
        org_id = org.id
        setup.commit()
    try:
        yield operator_id, secret, recovery_codes, now
    finally:
        # These requests need real concurrent commits rather than the usual
        # savepoint fixture. Remove only their own rows even when assertions fail.
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(AuditLog).where(AuditLog.org_id == org_id))
            cleanup.execute(delete(OperatorSession).where(OperatorSession.operator_id == operator_id))
            cleanup.execute(delete(Operator).where(Operator.id == operator_id))
            cleanup.execute(delete(Organization).where(Organization.id == org_id))
            cleanup.commit()


@pytest.fixture
def concurrent_mfa_app(db_engine, monkeypatch):
    app = create_app()

    def database():
        with Session(db_engine) as session:
            yield session

    app.dependency_overrides[deps.get_db] = database
    authenticate = deps._authenticate
    ready = Barrier(2)

    def overlapping_authentication(*args, **kwargs):
        bearer = authenticate(*args, **kwargs)
        # Both requests authenticate the live challenge before either consumes
        # it. This exercises stale state without changing verification itself.
        ready.wait(timeout=10)
        return bearer

    monkeypatch.setattr(deps, "_authenticate", overlapping_authentication)
    return app


@pytest.mark.parametrize(
    ("separate_challenges", "factor"),
    [(False, "totp"), (True, "totp"), (False, "different_totps"), (True, "recovery")],
)
def test_concurrent_mfa_creates_only_one_full_session(
    db_engine, enrolled_operator, concurrent_mfa_app, separate_challenges, factor
) -> None:
    operator_id, secret, recovery_codes, now = enrolled_operator
    with Session(db_engine) as setup:
        operator = setup.get(Operator, operator_id)
        _challenge, first = create_session(setup, operator, mfa_state=MFA_STATE_CHALLENGE)
        second = create_session(setup, operator, mfa_state=MFA_STATE_CHALLENGE)[1] if separate_challenges else first
        setup.commit()
    code = recovery_codes[0] if factor == "recovery" else mfa.totp(secret, now)
    second_code = mfa.totp(secret, now + timedelta(seconds=mfa.STEP_SECONDS)) if factor == "different_totps" else code

    def attempt(token_and_code):
        token, value = token_and_code
        with TestClient(concurrent_mfa_app) as client:
            return client.post(
                "/api/v1/auth/login/mfa", json={"code": value}, headers={"Authorization": f"Bearer {token}"}
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(attempt, [(first, code), (second, second_code)]))

    assert sorted(statuses) == ([200, 400] if separate_challenges else [200, 401])
    with Session(db_engine) as check:
        full_sessions = check.scalar(
            select(func.count())
            .select_from(OperatorSession)
            .where(OperatorSession.operator_id == operator_id, OperatorSession.mfa_state == MFA_STATE_VERIFIED)
        )
        assert full_sessions == 1
