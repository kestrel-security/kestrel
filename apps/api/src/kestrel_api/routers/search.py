# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-wide search API for the ⌘K command palette."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.db.models.org import Organization
from kestrel.search import SearchError, org_search
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
def search(
    q: str = Query(default="", max_length=200),
    limit_per_type: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Grouped entity search over identities, findings, and policies, for
    the command palette."""
    try:
        return org_search(db, org_id=org.id, query=q, limit_per_type=limit_per_type)
    except SearchError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
