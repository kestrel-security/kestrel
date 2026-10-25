# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- TOTP multi-factor authentication through the API.

Codes are computed with kestrel.auth.mfa against the secret the setup route
returns. A code is accepted once (replay protection), so a test that needs a
second code uses the next time step, which the ±1 step window accepts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kestrel.auth import mfa
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.org import Organization
from kestrel.testing import DEFAULT_PASSWORD, api_client, make_operator, make_organization
from sqlalchemy import select


def _code(secret: str, steps_ahead: int = 0) -> str:
    return mfa.totp(secret, datetime.now(UTC) + timedelta(seconds=steps_ahead * mfa.STEP_SECONDS))


def _enrol(client) -> tuple[str, list[str]]:
    setup = client.post("/api/v1/auth/mfa/setup")
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    activated = client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)})
    assert activated.status_code == 200, activated.text
    return secret, activated.json()["recovery_codes"]


def _login(client, email: str):
    return client.post(
        "/api/v1/auth/login", json={"email": email, "password": DEFAULT_PASSWORD}, headers={"Authorization": ""}
    )


def _as(client, token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _actions(db_session, org_id) -> list[str]:
    return list(db_session.scalars(select(AuditLog.action).where(AuditLog.org_id == org_id)).all())


def test_an_enrolled_sign_in_needs_the_second_factor(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    secret, _codes = _enrol(client)

    login = _login(client, client.kestrel_operator.email)
    assert login.status_code == 200
    assert login.json()["mfa_required"] is True
    assert login.json()["operator"] is None
    challenge = login.json()["token"]

    # The challenge alone reaches nothing else.
    blocked = client.get("/api/v1/findings", headers=_as(client, challenge))
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "mfa_challenge_required"

    finished = client.post("/api/v1/auth/login/mfa", json={"code": _code(secret, 1)}, headers=_as(client, challenge))
    assert finished.status_code == 200, finished.text
    session = finished.json()["token"]
    assert client.get("/api/v1/findings", headers=_as(client, session)).status_code == 200
    # The challenge is spent.
    replay = client.post("/api/v1/auth/login/mfa", json={"code": _code(secret, 1)}, headers=_as(client, challenge))
    assert replay.status_code == 401


def test_a_full_session_cannot_use_the_challenge_route(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/auth/login/mfa", json={"code": "123456"})

    assert response.status_code == 403


def test_wrong_codes_count_toward_lockout_and_spend_the_challenge(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    _secret, _codes = _enrol(client)
    challenge = _login(client, client.kestrel_operator.email).json()["token"]

    responses = [
        client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_as(client, challenge)) for _ in range(5)
    ]

    assert [r.status_code for r in responses] == [400, 400, 400, 400, 429]
    # The fifth wrong code locks the account; the response says so plainly.
    assert responses[-1].json()["detail"]["code"] == "account_locked"
    assert "Try again in 15 minutes" in responses[-1].json()["detail"]["message"]
    # And the challenge is gone.
    assert client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_as(client, challenge)).status_code == 401
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.locked_until is not None
    assert "auth.mfa_failed" in _actions(db_session, client.kestrel_org.id)


def test_signing_in_again_does_not_reset_the_wrong_code_count(db_session):
    # The password alone must not clear the lockout counter, or four wrong
    # codes, a fresh sign-in, and four more would never lock the account.
    client = api_client(db_session, OperatorRole.ANALYST)
    _secret, _codes = _enrol(client)
    first = _login(client, client.kestrel_operator.email).json()["token"]
    for _ in range(4):
        assert client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_as(client, first)).status_code == 400

    second = _login(client, client.kestrel_operator.email)
    assert second.status_code == 200
    locked = client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_as(client, second.json()["token"]))

    assert locked.status_code == 429
    assert locked.json()["detail"]["code"] == "account_locked"
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.locked_until is not None


def test_a_completed_second_factor_clears_the_wrong_code_count(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    secret, _codes = _enrol(client)
    challenge = _login(client, client.kestrel_operator.email).json()["token"]
    for _ in range(3):
        client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_as(client, challenge))
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.failed_login_attempts == 3

    ok = client.post("/api/v1/auth/login/mfa", json={"code": _code(secret, 1)}, headers=_as(client, challenge))

    assert ok.status_code == 200, ok.text
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.failed_login_attempts == 0


def test_a_recovery_code_works_once(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    _secret, codes = _enrol(client)

    first = _login(client, client.kestrel_operator.email).json()["token"]
    ok = client.post("/api/v1/auth/login/mfa", json={"code": codes[0].upper()}, headers=_as(client, first))
    assert ok.status_code == 200

    second = _login(client, client.kestrel_operator.email).json()["token"]
    reused = client.post("/api/v1/auth/login/mfa", json={"code": codes[0]}, headers=_as(client, second))
    assert reused.status_code == 400
    status = client.get("/api/v1/auth/mfa").json()
    assert status["recovery_codes_remaining"] == mfa.RECOVERY_CODE_COUNT - 1


def test_when_the_org_requires_mfa_an_unenrolled_sign_in_can_only_enrol(db_session):
    org = make_organization(db_session)
    org.require_mfa = True
    operator = make_operator(db_session, org, role=OperatorRole.ANALYST)
    db_session.commit()
    client = api_client(db_session, OperatorRole.ADMIN, org=org)

    login = _login(client, operator.email)
    assert login.json()["mfa_enrollment_required"] is True
    limited = login.json()["token"]

    blocked = client.get("/api/v1/findings", headers=_as(client, limited))
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "mfa_enrollment_required"
    me = client.get("/api/v1/auth/me", headers=_as(client, limited))
    assert me.json()["mfa_enrollment_required"] is True

    secret = client.post("/api/v1/auth/mfa/setup", headers=_as(client, limited)).json()["secret"]
    activated = client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)}, headers=_as(client, limited))
    assert activated.status_code == 200
    full = activated.json()["token"]
    assert full is not None
    assert client.get("/api/v1/findings", headers=_as(client, full)).status_code == 200
    # The limited session was replaced.
    assert client.get("/api/v1/auth/me", headers=_as(client, limited)).status_code == 401


def test_an_enrolment_only_session_is_short_lived(db_session):
    # It can only reach MFA setup, so it must not linger for a full session's 30 days.
    from kestrel.auth.service import MFA_ENROLLMENT_LIFETIME
    from kestrel.auth.tokens import hash_token
    from kestrel.db.models.operator import OperatorSession

    org = make_organization(db_session)
    org.require_mfa = True
    operator = make_operator(db_session, org, role=OperatorRole.ANALYST)
    db_session.commit()
    client = api_client(db_session, OperatorRole.ADMIN, org=org)

    token = _login(client, operator.email).json()["token"]

    row = db_session.scalars(select(OperatorSession).where(OperatorSession.token_hash == hash_token(token))).one()
    assert row.absolute_expires_at - row.created_at == MFA_ENROLLMENT_LIFETIME
    assert row.expires_at <= row.absolute_expires_at


def test_mfa_cannot_be_turned_off_while_the_org_requires_it(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    secret, _codes = _enrol(client)
    db_session.get(Organization, client.kestrel_org.id).require_mfa = True
    db_session.commit()

    response = client.post("/api/v1/auth/mfa/disable", json={"password": DEFAULT_PASSWORD, "code": _code(secret, 1)})

    assert response.status_code == 409


def test_turning_mfa_off_needs_the_password_and_a_code(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    secret, _codes = _enrol(client)

    wrong_password = client.post("/api/v1/auth/mfa/disable", json={"password": "nope", "code": _code(secret, 1)})
    assert wrong_password.status_code == 400
    ok = client.post("/api/v1/auth/mfa/disable", json={"password": DEFAULT_PASSWORD, "code": _code(secret, 1)})
    assert ok.status_code == 204
    assert _login(client, client.kestrel_operator.email).json()["mfa_required"] is False


def test_setting_up_again_while_enrolled_is_refused(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    _enrol(client)

    assert client.post("/api/v1/auth/mfa/setup").status_code == 409


def test_an_admin_reset_removes_mfa_and_ends_sessions(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)
    _enrol(analyst)

    response = admin.post(f"/api/v1/operators/{analyst.kestrel_operator.id}/mfa/reset")

    assert response.status_code == 204
    assert analyst.get("/api/v1/auth/me").status_code == 401
    assert _login(admin, analyst.kestrel_operator.email).json()["mfa_required"] is False
    assert "operator.mfa_reset" in _actions(db_session, admin.kestrel_org.id)
    assert admin.post(f"/api/v1/operators/{admin.kestrel_operator.id}/mfa/reset").status_code == 409


def test_an_api_token_cannot_mint_another_for_an_operator_with_mfa(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    _enrol(client)
    created = client.post("/api/v1/api-tokens", json={"name": "ci"})
    assert created.status_code == 201  # from the signed-in session
    token = created.json()["token"]

    from_token = client.post("/api/v1/api-tokens", json={"name": "copy"}, headers=_as(client, token))

    assert from_token.status_code == 403
    # The token itself still works without a second factor.
    assert client.get("/api/v1/findings", headers=_as(client, token)).status_code == 200


def test_org_security_reports_who_has_not_enrolled(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)

    updated = admin.patch("/api/v1/org/security", json={"require_mfa": True})

    assert updated.status_code == 200
    assert updated.json() == {"require_mfa": True, "active_operators_without_mfa": 2}
    assert "org.require_mfa_enabled" in _actions(db_session, admin.kestrel_org.id)


def test_reusing_the_code_that_just_worked_says_to_wait_for_the_next_one(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    secret = client.post("/api/v1/auth/mfa/setup").json()["secret"]
    code = _code(secret)
    assert client.post("/api/v1/auth/mfa/activate", json={"code": code}).status_code == 200
    challenge = _login(client, client.kestrel_operator.email).json()["token"]

    reused = client.post("/api/v1/auth/login/mfa", json={"code": code}, headers=_as(client, challenge))

    assert reused.status_code == 400
    assert reused.json()["detail"]["code"] == "code_already_used"
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.failed_login_attempts == 0
