# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Change feed API.

"What changed across every connected app, and which of it matters" — read-only
over the sync diff. Per-run drift stays on the connectors router.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.changes import ChangeFeedError, change_feed, resolve_connector_instance
from kestrel.changes.classify import ChangeClass, Significance
from kestrel.db.models.org import Organization
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db

router = APIRouter(prefix="/changes", tags=["changes"])


@router.get("")
def list_changes(
    window_hours: int = Query(default=168, ge=1, le=24 * 90),
    change_class: list[str] | None = Query(default=None),
    min_significance: str | None = Query(
        default="medium",
        description="Minimum significance (high / medium / low). Default medium hides low telemetry.",
    ),
    connector_instance_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Classified changes for the org, most significant first."""
    try:
        if connector_instance_id is not None:
            resolve_connector_instance(db, org.id, connector_instance_id)
        return change_feed(
            db,
            org.id,
            window_hours=window_hours,
            change_classes=change_class,
            min_significance=min_significance,
            connector_instance_id=connector_instance_id,
            search=search,
            limit=limit,
            offset=offset,
        )
    except ChangeFeedError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/classes")
def list_change_classes(_: Organization = Depends(get_current_org)) -> dict:
    """Vocabulary for building filters without hardcoding it in the client."""
    return {
        "classes": [c.value for c in ChangeClass],
        "significance": [s.value for s in Significance],
    }
