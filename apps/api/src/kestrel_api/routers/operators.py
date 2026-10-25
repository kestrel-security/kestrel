# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator (Kestrel login account) management. Listing is available to any
authenticated operator -- e.g. the finding-assignment picker in the web UI
needs every operator to be able to list teammates -- while mutations
(create/edit role/deactivate/reset password) are admin-only."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from kestrel.audit.service import record_audit_event
from kestrel.auth import mfa
from kestrel.auth.passwords import PasswordPolicyError, hash_password, validate_password_policy
from kestrel.auth.service import revoke_operator_api_tokens, revoke_operator_sessions
from kestrel.auth.tokens import hash_token
from kestrel.db.models.operator import Operator, OperatorRole
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_db, require_role

router = APIRouter(prefix="/operators", tags=["operators"])


def _operator_out(operator: Operator) -> dict:
    return {
        "id": operator.id,
        "email": operator.email,
        "display_name": operator.display_name,
        "role": operator.role.value,
        "is_active": operator.is_active,
        "mfa_enabled": mfa.is_enrolled(operator),
        "last_login_at": operator.last_login_at.isoformat() if operator.last_login_at else None,
    }


@router.get("")
def list_operators(db: Session = Depends(get_db), operator: Operator = Depends(get_current_operator)) -> list[dict]:
    rows = db.scalars(select(Operator).where(Operator.org_id == operator.org_id).order_by(Operator.email)).all()
    return [_operator_out(o) for o in rows]


@router.get("/{operator_id}")
def get_operator(
    operator_id: uuid.UUID, db: Session = Depends(get_db), operator: Operator = Depends(get_current_operator)
) -> dict:
    target = db.get(Operator, operator_id)
    if target is None or target.org_id != operator.org_id:
        raise HTTPException(status_code=404, detail="Operator not found")
    return _operator_out(target)


class OperatorCreate(BaseModel):
    email: str
    display_name: str | None = None
    role: str
    password: str


@router.post("", status_code=201)
def create_operator(
    body: OperatorCreate,
    db: Session = Depends(get_db),
    current: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    existing = db.scalars(
        select(Operator).where(Operator.org_id == current.org_id, func.lower(Operator.email) == body.email.strip().lower())
    ).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="An operator with this email already exists")

    try:
        validate_password_policy(body.password)
        role = OperatorRole(body.role)
    except (PasswordPolicyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    new_operator = Operator(
        id=uuid.uuid4(),
        org_id=current.org_id,
        email=body.email,
        display_name=body.display_name,
        password_hash=hash_password(body.password),
        role=role,
        is_active=True,
    )
    db.add(new_operator)
    db.flush()
    record_audit_event(
        db,
        org_id=current.org_id,
        actor_operator_id=current.id,
        action="operator.created",
        target_type="operator",
        target_id=new_operator.id,
        context={"email": body.email, "role": role.value},
    )
    db.commit()
    return _operator_out(new_operator)


class OperatorPatch(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


@router.patch("/{operator_id}")
def patch_operator(
    operator_id: uuid.UUID,
    body: OperatorPatch,
    db: Session = Depends(get_db),
    current: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    target = db.get(Operator, operator_id)
    if target is None or target.org_id != current.org_id:
        raise HTTPException(status_code=404, detail="Operator not found")

    deactivating = body.is_active is False and target.is_active
    demoting = body.role is not None and body.role != OperatorRole.ADMIN.value and target.role == OperatorRole.ADMIN
    if target.id == current.id and (deactivating or demoting):
        raise HTTPException(status_code=409, detail="You cannot deactivate or demote your own account; ask another admin.")
    if (deactivating or demoting) and target.role == OperatorRole.ADMIN and target.is_active:
        other_admins = db.scalar(
            select(func.count())
            .select_from(Operator)
            .where(
                Operator.org_id == current.org_id,
                Operator.id != target.id,
                Operator.role == OperatorRole.ADMIN,
                Operator.is_active.is_(True),
            )
        )
        if not other_admins:
            raise HTTPException(status_code=409, detail="This is the organization's last active admin.")

    changes: dict = {}
    if body.display_name is not None:
        target.display_name = body.display_name
        changes["display_name"] = body.display_name
    if body.role is not None:
        try:
            target.role = OperatorRole(body.role)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        changes["role"] = target.role.value
    if body.is_active is not None:
        target.is_active = body.is_active
        changes["is_active"] = body.is_active
    if deactivating:
        # Lookup already refuses an inactive operator's credentials, but a
        # later reactivation must not bring old sessions and tokens back.
        changes["sessions_revoked"] = revoke_operator_sessions(db, target.id)
        changes["api_tokens_revoked"] = revoke_operator_api_tokens(db, target.id)

    if changes:
        record_audit_event(
            db,
            org_id=current.org_id,
            actor_operator_id=current.id,
            action="operator.updated",
            target_type="operator",
            target_id=target.id,
            context=changes,
        )
    db.commit()
    return _operator_out(target)


class SetPasswordRequest(BaseModel):
    password: str
    # An admin reset usually answers a suspected compromise, so the
    # operator's API tokens go too unless the admin opts out. Sessions are
    # always revoked.
    revoke_api_tokens: bool = True


@router.post("/{operator_id}/set-password", status_code=204)
def set_password(
    operator_id: uuid.UUID,
    body: SetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> None:
    target = db.get(Operator, operator_id)
    if target is None or target.org_id != current.org_id:
        raise HTTPException(status_code=404, detail="Operator not found")
    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    target.password_hash = hash_password(body.password)
    target.failed_login_attempts = 0
    target.locked_until = None
    # An admin resetting their own password keeps the session doing it.
    keep = hash_token(request.state.raw_token) if target.id == current.id else None
    sessions_revoked = revoke_operator_sessions(db, target.id, keep_token_hash=keep)
    api_tokens_revoked = revoke_operator_api_tokens(db, target.id) if body.revoke_api_tokens else 0
    record_audit_event(
        db,
        org_id=current.org_id,
        actor_operator_id=current.id,
        action="operator.password_reset",
        target_type="operator",
        target_id=target.id,
        context={"sessions_revoked": sessions_revoked, "api_tokens_revoked": api_tokens_revoked},
    )
    db.commit()


@router.post("/{operator_id}/mfa/reset", status_code=204)
def reset_mfa(
    operator_id: uuid.UUID,
    db: Session = Depends(get_db),
    current: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> None:
    """Remove another operator's second factor (lost device) and end their sessions.

    Their next sign-in is password only, or asks them to enrol again if the
    organization requires MFA. Admins turn off their own MFA from Settings →
    Account instead, which needs a current code.
    """
    target = db.get(Operator, operator_id)
    if target is None or target.org_id != current.org_id:
        raise HTTPException(status_code=404, detail="Operator not found")
    if target.id == current.id:
        raise HTTPException(status_code=409, detail="Turn off your own two-factor authentication from your account.")
    sessions_revoked = mfa.reset(db, target)
    record_audit_event(
        db,
        org_id=current.org_id,
        actor_operator_id=current.id,
        action="operator.mfa_reset",
        target_type="operator",
        target_id=target.id,
        context={"sessions_revoked": sessions_revoked},
    )
    db.commit()
