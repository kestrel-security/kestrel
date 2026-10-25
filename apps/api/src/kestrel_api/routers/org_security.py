# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Organization-wide sign-in policy: whether every operator must use MFA.

Turning the requirement on signs nobody out. It applies at each operator's
next password sign-in, when anyone without a second factor is sent to set
one up before they can do anything else.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role

router = APIRouter(prefix="/org/security", tags=["operators"])


def _security_out(db: Session, org: Organization) -> dict:
    not_enrolled = db.scalar(
        select(func.count())
        .select_from(Operator)
        .where(Operator.org_id == org.id, Operator.is_active.is_(True), Operator.mfa_enabled_at.is_(None))
    )
    return {"require_mfa": org.require_mfa, "active_operators_without_mfa": int(not_enrolled or 0)}


@router.get("")
def get_security(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _admin: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    return _security_out(db, org)


class SecurityIn(BaseModel):
    require_mfa: bool


@router.patch("")
def update_security(
    body: SecurityIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    admin: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict:
    if org.require_mfa != body.require_mfa:
        org.require_mfa = body.require_mfa
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=admin.id,
            action="org.require_mfa_enabled" if body.require_mfa else "org.require_mfa_disabled",
        )
        db.commit()
    return _security_out(db, org)
