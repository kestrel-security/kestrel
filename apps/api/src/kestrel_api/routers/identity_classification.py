# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Settings -> Identity classification: operator rules that assign a worker type.

Admin-only. The rule list is replaced as a whole, in priority order, and
every identity in the org is reclassified in the same transaction, so a saved
rule is visible to policies and the Identities page without a re-sync.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.identities.classification import (
    ClassificationRuleError,
    RuleSpec,
    list_rules,
    preview_rules,
    reclassify_identities,
    replace_rules,
    rules_out,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role

router = APIRouter(prefix="/settings/identity-classification", tags=["settings-identity-classification"])

MAX_RULES = 200


class ClassificationRuleIn(BaseModel):
    id: uuid.UUID | None = None
    worker_type: str = Field(..., min_length=1, max_length=32)
    match_kind: str = Field(..., min_length=1, max_length=32)
    match_value: str = Field(..., min_length=1, max_length=512)
    application_type: str | None = Field(default=None, max_length=64)
    label: str | None = Field(default=None, max_length=200)
    is_enabled: bool = True

    def to_spec(self) -> RuleSpec:
        return RuleSpec(
            worker_type=self.worker_type,
            match_kind=self.match_kind,
            match_value=self.match_value,
            application_type=self.application_type,
            label=self.label,
            is_enabled=self.is_enabled,
            id=self.id,
        )


class ClassificationRuleOut(BaseModel):
    id: uuid.UUID
    priority: int
    is_enabled: bool
    worker_type: str
    match_kind: str
    match_value: str
    application_type: str | None = None
    label: str | None = None


class ClassificationRulesOut(BaseModel):
    rules: list[ClassificationRuleOut]
    match_kinds: list[str]
    worker_types: list[str]
    reclassified: int | None = None


class ClassificationRulesPutIn(BaseModel):
    rules: list[ClassificationRuleIn] = Field(default_factory=list, max_length=MAX_RULES)


class ClassificationPreviewOut(BaseModel):
    counts: dict[str, int]
    changed: int
    matched_by_rule: list[int]


@router.get("")
def get_classification_rules(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> ClassificationRulesOut:
    return ClassificationRulesOut(**rules_out(list_rules(db, org.id)))


@router.put("")
def put_classification_rules(
    body: ClassificationRulesPutIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> ClassificationRulesOut:
    try:
        rows = replace_rules(db, org.id, [rule.to_spec() for rule in body.rules], actor_operator_id=actor.id)
        reclassified = reclassify_identities(db, org.id)
        record_audit_event(
            db,
            org_id=org.id,
            actor_operator_id=actor.id,
            action="identity_classification.updated",
            target_type="org_identity_classification_rules",
            target_id=None,
            context={"rule_count": len(rows), "reclassified": reclassified},
        )
        db.commit()
    except ClassificationRuleError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ClassificationRulesOut(**rules_out(list_rules(db, org.id)), reclassified=reclassified)


@router.post("/preview")
def preview_classification_rules(
    body: ClassificationRulesPutIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    _actor: Operator = Depends(require_role(OperatorRole.ADMIN)),
) -> ClassificationPreviewOut:
    try:
        return ClassificationPreviewOut(**preview_rules(db, org.id, [rule.to_spec() for rule in body.rules]))
    except ClassificationRuleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
