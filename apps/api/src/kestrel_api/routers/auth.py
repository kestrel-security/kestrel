# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Login/logout/me for Kestrel operators. See deps.py for the bearer-token
mechanism and docs/adr/0008-opaque-tokens-for-operator-auth.md for the
overall design.

FastAPI never sets or reads a cookie here -- the Next.js app is responsible
for turning this endpoint's JSON token response into an httponly cookie on
its own domain (see apps/web/src/lib/actions.ts's `login` action)."""

from __future__ import annotations

from datetime import UTC, datetime
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Request
from kestrel.audit.service import record_audit_event
from kestrel.auth import mfa
from kestrel.auth.passwords import PasswordPolicyError, hash_password, validate_password_policy, verify_password
from kestrel.auth.service import (
    MFA_CHALLENGE_MAX_FAILURES,
    BearerAuth,
    authenticate_operator,
    clear_failed_attempts,
    create_session,
    revoke_operator_sessions,
    revoke_session,
)
from kestrel.auth.tokens import hash_token
from kestrel.db.models.operator import MFA_STATE_CHALLENGE, MFA_STATE_ENROLL, Operator, OperatorSession
from kestrel.db.models.org import Organization
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.client_ip import client_ip
from kestrel_api.deps import (
    get_bearer_any,
    get_bearer_for_mfa_challenge,
    get_bearer_for_mfa_setup,
    get_current_operator,
    get_db,
)
from kestrel_api.middleware.rate_limit import check_login_email_limit, rate_limit_headers

router = APIRouter(prefix="/auth", tags=["auth"])


def _operator_out(operator: Operator) -> dict:
    return {
        "mfa_enabled": mfa.is_enrolled(operator),
        "id": operator.id,
        "email": operator.email,
        "display_name": operator.display_name,
        "role": operator.role.value,
        "is_active": operator.is_active,
        "last_login_at": operator.last_login_at.isoformat() if operator.last_login_at else None,
        "ui_preferences": operator.ui_preferences or {},
    }


class LoginRequest(BaseModel):
    # RFC 5321's longest address; a password past 1 KiB is not a password,
    # and every byte of it would go through Argon2.
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class LoginResponse(BaseModel):
    """A session token. With ``mfa_required`` it only reaches
    ``POST /auth/login/mfa`` (for five minutes); with
    ``mfa_enrollment_required`` it only reaches the MFA setup routes."""

    token: str
    operator: dict | None = None
    mfa_required: bool = False
    mfa_enrollment_required: bool = False


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    try:
        org = db.scalars(select(Organization)).first()
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Database is not initialized yet -- run migrations and `kestrel init` first.",
        ) from exc
    if org is None:
        raise HTTPException(status_code=503, detail="No organization configured yet -- run `kestrel init` first.")

    # Per-account bucket alongside the middleware's per-IP one.
    email_limit = check_login_email_limit(body.email)
    if email_limit is not None and not email_limit.allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts for this account. Retry later.",
            headers=rate_limit_headers(email_limit),
        )

    operator = authenticate_operator(db, org.id, body.email, body.password)
    if operator is None:
        record_audit_event(
            db, org_id=org.id, actor_operator_id=None, action="auth.login_failed", context={"email": body.email}
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    ip_address, user_agent = client_ip(request), request.headers.get("user-agent")
    if mfa.is_enrolled(operator):
        _session_row, raw_token = create_session(
            db, operator, ip_address=ip_address, user_agent=user_agent, mfa_state=MFA_STATE_CHALLENGE
        )
        db.commit()
        return LoginResponse(token=raw_token, mfa_required=True)
    if org.require_mfa:
        _session_row, raw_token = create_session(
            db, operator, ip_address=ip_address, user_agent=user_agent, mfa_state=MFA_STATE_ENROLL
        )
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=operator.id,
            action="auth.login_mfa_enrollment_required",
            target_type="operator",
            target_id=operator.id,
        )
        db.commit()
        return LoginResponse(token=raw_token, operator=_operator_out(operator), mfa_enrollment_required=True)

    _session_row, raw_token = create_session(db, operator, ip_address=ip_address, user_agent=user_agent)
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=operator.id,
        action="auth.login_succeeded",
        target_type="operator",
        target_id=operator.id,
    )
    db.commit()

    return LoginResponse(token=raw_token, operator=_operator_out(operator))


def _locked_out(operator: Operator) -> bool:
    return operator.locked_until is not None and operator.locked_until > datetime.now(UTC)


def _locked_error(operator: Operator) -> HTTPException:
    """The password was right, so saying the account is locked reveals nothing new."""
    assert operator.locked_until is not None
    minutes = max(1, ceil((operator.locked_until - datetime.now(UTC)).total_seconds() / 60))
    return HTTPException(
        status_code=429,
        detail={
            "code": "account_locked",
            "message": f"Too many incorrect codes. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
        },
    )


class MfaLoginRequest(BaseModel):
    code: str


@router.post("/login/mfa", response_model=LoginResponse)
def login_mfa(
    body: MfaLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    bearer: BearerAuth = Depends(get_bearer_for_mfa_challenge),
) -> LoginResponse:
    """Finish a sign-in with a TOTP or recovery code.

    The challenge session is spent either way it ends: on success it is
    replaced by a full session; after too many wrong codes it is revoked and
    the operator signs in again. Wrong codes also count toward the account
    lockout.
    """
    operator, challenge = bearer.operator, bearer.session_row
    assert challenge is not None  # the challenge dependency only accepts sessions
    # Authentication commits its session touch. Recheck under locks in this
    # transaction: another request may have consumed the challenge meanwhile.
    mfa.lock_operator(db, operator)
    db.refresh(challenge, with_for_update=True)
    now = datetime.now(UTC)
    if (
        not operator.is_active
        or challenge.revoked_at is not None
        or challenge.mfa_state != MFA_STATE_CHALLENGE
        or challenge.expires_at <= now
        or challenge.absolute_expires_at <= now
    ):
        raise HTTPException(status_code=401, detail="Invalid, expired, or revoked token")
    email_limit = check_login_email_limit(operator.email)
    if email_limit is not None and not email_limit.allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts for this account. Retry later.",
            headers=rate_limit_headers(email_limit),
        )
    if _locked_out(operator):
        revoke_session(challenge)
        db.commit()
        raise _locked_error(operator)
    replayed = mfa.code_already_used(operator, body.code, now)
    method = None if replayed else mfa.verify_second_factor(db, operator, body.code, now=now)
    if method is None:
        challenge.mfa_failed_attempts += 1
        spent = challenge.mfa_failed_attempts >= MFA_CHALLENGE_MAX_FAILURES
        record_audit_event(
            db,
            org_id=operator.org_id,
            actor_operator_id=operator.id,
            action="auth.mfa_failed",
            target_type="operator",
            target_id=operator.id,
        )
        db.refresh(operator, ["locked_until"])
        if _locked_out(operator):
            revoke_session(challenge)
            db.commit()
            raise _locked_error(operator)
        if spent:
            revoke_session(challenge)
            db.commit()
            raise HTTPException(status_code=401, detail="Too many incorrect codes. Sign in again.")
        db.commit()
        # 400, not 401: the challenge itself is still valid until it is spent.
        if replayed:
            raise HTTPException(
                status_code=400,
                detail={"code": "code_already_used", "message": "That code was just used. Wait for the next one."},
            )
        raise HTTPException(status_code=400, detail={"code": "invalid_code", "message": "That code is not valid."})

    # The password step leaves the counter alone for enrolled operators; the
    # sign-in is complete only now.
    clear_failed_attempts(operator)
    revoke_session(challenge)
    _session_row, raw_token = create_session(
        db, operator, ip_address=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="auth.login_succeeded",
        target_type="operator",
        target_id=operator.id,
        context={"second_factor": method},
    )
    db.commit()
    return LoginResponse(token=raw_token, operator=_operator_out(operator))


@router.post("/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db), bearer: BearerAuth = Depends(get_bearer_any)) -> None:
    operator = bearer.operator
    raw_token = request.state.raw_token
    session_row = db.scalars(
        select(OperatorSession).where(OperatorSession.token_hash == hash_token(raw_token))
    ).one_or_none()
    if session_row is None:
        raise HTTPException(
            status_code=400,
            detail="This credential is an API token, not a session -- revoke it via DELETE /api-tokens/{id} instead.",
        )
    revoke_session(session_row)
    record_audit_event(db, org_id=operator.org_id, actor_operator_id=operator.id, action="auth.logout")
    db.commit()


@router.get("/me")
def me(bearer: BearerAuth = Depends(get_bearer_for_mfa_setup)) -> dict:
    """The signed-in operator. Also answers a session limited to MFA setup,
    flagged with ``mfa_enrollment_required``, so the web can route it there."""
    out = _operator_out(bearer.operator)
    out["mfa_enrollment_required"] = bearer.mfa_state == MFA_STATE_ENROLL
    return out


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@router.post("/change-password", status_code=204)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> None:
    """Change the caller's password and sign out their other sessions.

    The session making the request stays valid; every other session is
    revoked, so one opened with the old password (possibly by whoever made
    the change necessary) stops working. API tokens are left alone: they are
    deliberate, named credentials, revocable from the API tokens page.
    """
    if request.state.bearer.is_api_token:
        # A token never passed a second factor and is exactly what a phished
        # password plus a leaked token would use to lock the real user out.
        raise HTTPException(status_code=403, detail="Change your password from a signed-in session, not an API token.")
    if operator.password_hash is None or not verify_password(body.old_password, operator.password_hash):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    operator.password_hash = hash_password(body.new_password)
    sessions_revoked = revoke_operator_sessions(db, operator.id, keep_token_hash=hash_token(request.state.raw_token))
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="auth.password_changed",
        context={"other_sessions_revoked": sessions_revoked},
    )
    db.commit()
