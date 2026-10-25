# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Two-factor authentication (TOTP) for the signed-in operator.

Setup and activation also answer a session limited to enrolment, the one
`POST /auth/login` issues when the organization requires MFA and the
operator has none yet; activating rotates that session into a full one.
Turning MFA off and regenerating recovery codes need a full session. See
kestrel.auth.mfa for the scheme.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from kestrel.audit.service import record_audit_event
from kestrel.auth import mfa
from kestrel.auth.passwords import verify_password
from kestrel.auth.service import BearerAuth, create_session, revoke_session
from kestrel.db.models.operator import MFA_STATE_ENROLL, Operator
from kestrel.db.models.org import Organization
from pydantic import BaseModel
from sqlalchemy.orm import Session

from kestrel_api.client_ip import client_ip
from kestrel_api.deps import get_bearer_for_mfa_setup, get_current_operator, get_db

router = APIRouter(prefix="/auth/mfa", tags=["auth"])


def _require_session(bearer: BearerAuth) -> None:
    """Enrolment and recovery-code changes alter the second factor itself, so
    they must come from a signed-in session; an API token never passed MFA
    and could enrol an attacker's authenticator or mint new recovery codes."""
    if bearer.is_api_token:
        raise HTTPException(
            status_code=403, detail="Manage two-factor authentication from a signed-in session, not an API token."
        )


def _org_requires_mfa(db: Session, operator: Operator) -> bool:
    org = db.get(Organization, operator.org_id)
    return bool(org and org.require_mfa)


@router.get("")
def mfa_status(db: Session = Depends(get_db), bearer: BearerAuth = Depends(get_bearer_for_mfa_setup)) -> dict:
    """Whether the caller has two-factor authentication on, and how many recovery codes are left."""
    operator = bearer.operator
    enrolled = mfa.is_enrolled(operator)
    return {
        "enabled": enrolled,
        "enabled_at": operator.mfa_enabled_at.isoformat() if operator.mfa_enabled_at else None,
        "recovery_codes_remaining": mfa.remaining_recovery_codes(db, operator) if enrolled else 0,
        "required_by_org": _org_requires_mfa(db, operator),
    }


@router.post("/setup")
def mfa_setup(db: Session = Depends(get_db), bearer: BearerAuth = Depends(get_bearer_for_mfa_setup)) -> dict:
    """Start enrolment: a new secret to add to an authenticator app.

    The secret is stored, encrypted, but not in force until ``/activate``
    confirms a code from it. Calling this again replaces a pending secret.
    """
    _require_session(bearer)
    try:
        secret, uri = mfa.start_enrolment(bearer.operator)
    except mfa.MfaError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return {"secret": secret, "otpauth_uri": uri}


class CodeIn(BaseModel):
    code: str


@router.post("/activate")
def mfa_activate(
    body: CodeIn,
    request: Request,
    db: Session = Depends(get_db),
    bearer: BearerAuth = Depends(get_bearer_for_mfa_setup),
) -> dict:
    """Turn MFA on with a first code from the authenticator. Returns the
    recovery codes, shown only this once, and, for a session that was
    limited to enrolment, a full session ``token`` to replace it."""
    _require_session(bearer)
    operator = bearer.operator
    try:
        codes = mfa.activate(db, operator, body.code)
    except mfa.MfaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="auth.mfa_enabled",
        target_type="operator",
        target_id=operator.id,
    )
    token = None
    if bearer.mfa_state == MFA_STATE_ENROLL and bearer.session_row is not None:
        revoke_session(bearer.session_row)
        _session, token = create_session(
            db, operator, ip_address=client_ip(request), user_agent=request.headers.get("user-agent")
        )
    db.commit()
    return {"recovery_codes": codes, "token": token}


class DisableIn(BaseModel):
    password: str
    code: str


@router.post("/disable", status_code=204)
def mfa_disable(body: DisableIn, db: Session = Depends(get_db), operator: Operator = Depends(get_current_operator)) -> None:
    """Turn MFA off. Needs the password and a current code, and is refused
    while the organization requires MFA."""
    if _org_requires_mfa(db, operator):
        raise HTTPException(status_code=409, detail="Your organization requires two-factor authentication.")
    if not mfa.is_enrolled(operator):
        raise HTTPException(status_code=409, detail="Two-factor authentication is not on.")
    if operator.password_hash is None or not verify_password(body.password, operator.password_hash):
        raise HTTPException(status_code=400, detail="Password is incorrect.")
    if mfa.verify_second_factor(db, operator, body.code) is None:
        db.commit()  # keep the failed-attempt count
        raise HTTPException(status_code=400, detail="That code is not valid.")
    mfa.disable(db, operator)
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="auth.mfa_disabled",
        target_type="operator",
        target_id=operator.id,
    )
    db.commit()


@router.post("/recovery-codes")
def mfa_regenerate_recovery_codes(
    body: CodeIn,
    request: Request,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> dict:
    """Replace every recovery code with a fresh set (shown only this once)."""
    _require_session(request.state.bearer)
    if not mfa.is_enrolled(operator):
        raise HTTPException(status_code=409, detail="Two-factor authentication is not on.")
    if mfa.verify_second_factor(db, operator, body.code) is None:
        db.commit()
        raise HTTPException(status_code=400, detail="That code is not valid.")
    codes = mfa.replace_recovery_codes(db, operator, datetime.now(UTC))
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="auth.mfa_recovery_codes_regenerated",
        target_type="operator",
        target_id=operator.id,
    )
    db.commit()
    return {"recovery_codes": codes}
