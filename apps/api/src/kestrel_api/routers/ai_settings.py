# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org LLM settings for policy AI drafts.

Admin-only: API keys are envelope-encrypted; GET returns status only.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.policies.llm_settings import (
    LlmSettingsError,
    clear_org_llm_settings,
    get_org_llm_settings,
    settings_out,
    upsert_org_llm_settings,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role

router = APIRouter(prefix="/settings/ai", tags=["settings-ai"])


class AiSettingsOut(BaseModel):
    configured: bool
    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    is_enabled: bool = False
    api_key_configured: bool = False
    defaults: dict


class AiSettingsPutIn(BaseModel):
    provider: str = Field(..., min_length=1, max_length=32)
    model: str | None = Field(default=None, max_length=128)
    base_url: str | None = Field(default=None, max_length=512)
    api_key: str | None = Field(default=None, max_length=4096)
    is_enabled: bool = True


@router.get("")
def get_ai_settings(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> AiSettingsOut:
    row = get_org_llm_settings(db, org.id)
    return AiSettingsOut(**settings_out(row))


@router.put("")
def put_ai_settings(
    body: AiSettingsPutIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> AiSettingsOut:
    try:
        row = upsert_org_llm_settings(
            db,
            org_id=org.id,
            provider=body.provider,
            model=body.model,
            base_url=body.base_url,
            api_key=body.api_key,
            is_enabled=body.is_enabled,
        )
        db.flush()
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="settings.ai_updated",
            target_type="org_llm_settings",
            target_id=row.id,
            context={
                "provider": row.provider,
                "model": row.model,
                "is_enabled": row.is_enabled,
                "api_key_rotated": bool(body.api_key and body.api_key.strip()),
            },
        )
        db.commit()
        db.refresh(row)
    except LlmSettingsError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AiSettingsOut(**settings_out(row))


@router.delete("")
def delete_ai_settings(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> dict[str, bool]:
    existing = get_org_llm_settings(db, org.id)
    target_id = existing.id if existing else None
    cleared = clear_org_llm_settings(db, org.id)
    if cleared:
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="settings.ai_cleared",
            target_type="org_llm_settings",
            target_id=target_id,
            context={},
        )
    db.commit()
    return {"cleared": cleared}
