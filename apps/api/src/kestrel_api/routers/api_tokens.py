# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""API token management. Any authenticated operator manages their own
tokens regardless of role (even a Read-only analyst needs a CLI token);
admins can additionally view/revoke another operator's tokens via
?operator_id=."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from kestrel.audit.service import record_audit_event
from kestrel.auth.rbac import role_satisfies
from kestrel.auth.service import create_api_token, revoke_api_token
from kestrel.db.models.operator import ApiToken, Operator, OperatorRole
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_operator, get_db

router = APIRouter(prefix="/api-tokens", tags=["api-tokens"])


def _token_out(token: ApiToken) -> dict:
    return {
        "id": token.id,
        "name": token.name,
        "token_prefix": token.token_prefix,
        "operator_id": token.operator_id,
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
        "created_at": token.created_at.isoformat(),
    }


@router.get("")
def list_tokens(
    operator_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> list[dict]:
    target_operator_id = operator.id
    if operator_id is not None and operator_id != operator.id:
        if not role_satisfies(operator.role, OperatorRole.ADMIN):
            raise HTTPException(status_code=403, detail="Only admins can view another operator's tokens")
        target_operator_id = operator_id

    rows = db.scalars(
        select(ApiToken).where(ApiToken.org_id == operator.org_id, ApiToken.operator_id == target_operator_id)
    ).all()
    return [_token_out(t) for t in rows]


#: Longest lifetime a token may be minted with. Unbounded input overflowed
#: datetime arithmetic into a 500; a year is plenty for CI credentials.
MAX_TOKEN_LIFETIME_DAYS = 365


class ApiTokenCreate(BaseModel):
    name: str
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_TOKEN_LIFETIME_DAYS)


class ApiTokenCreated(BaseModel):
    token: str
    id: uuid.UUID
    name: str
    token_prefix: str


@router.post("", status_code=201)
def create_token(
    body: ApiTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> ApiTokenCreated:
    # API tokens bypass the second factor by design (automation), so one is
    # minted only from a signed-in session -- never from another API token,
    # which only proves a token was copied. Letting a token mint tokens would
    # also let a leaked, expiring or soon-revoked credential replace itself
    # with a fresh, unexpiring one.
    if request.state.bearer.is_api_token:
        raise HTTPException(
            status_code=403,
            detail="Create API tokens from a signed-in session, not with another API token.",
        )
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    token_row, raw_token = create_api_token(db, operator, body.name, expires_at=expires_at)
    # A long-lived credential that bypasses MFA by design: its creation has to
    # be reconstructible after a compromise.
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="api_token.created",
        target_type="api_token",
        target_id=token_row.id,
        context={"name": body.name, "expires_at": expires_at.isoformat() if expires_at else None},
    )
    db.commit()
    return ApiTokenCreated(token=raw_token, id=token_row.id, name=token_row.name, token_prefix=token_row.token_prefix)


@router.delete("/{token_id}", status_code=204)
def revoke_token(
    token_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator),
) -> None:
    token_row = db.get(ApiToken, token_id)
    if token_row is None or token_row.org_id != operator.org_id:
        raise HTTPException(status_code=404, detail="Token not found")
    if token_row.operator_id != operator.id and not role_satisfies(operator.role, OperatorRole.ADMIN):
        raise HTTPException(status_code=403, detail="You can only revoke your own tokens")

    revoke_api_token(token_row)
    record_audit_event(
        db,
        org_id=operator.org_id,
        actor_operator_id=operator.id,
        action="api_token.revoked",
        target_type="api_token",
        target_id=token_row.id,
        context={"name": token_row.name, "owner_operator_id": str(token_row.operator_id)},
    )
    db.commit()
