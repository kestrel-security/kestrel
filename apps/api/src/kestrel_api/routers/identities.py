# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identities API: the paginated list (with privileged and cross-app collapse
filters) behind the Identities page and the Explore picker, correlated
clusters, and per-identity detail, access, and overview for the identity page.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.db.base import is_active
from kestrel.db.models.identity import WORKER_TYPES, Identity, IdentityType
from kestrel.db.models.org import Organization
from kestrel.graph.queries import privileged_identity_ids_subquery
from kestrel.identities.detail import identity_reachable_access
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db
from kestrel_api.pagination import MAX_LIMIT, apply_keyset, build_page, encode_cursor, normalize_limit

router = APIRouter(prefix="/identities", tags=["identities"])


def _serialize_identity(
    identity: Identity,
    *,
    privileged_ids: set[uuid.UUID],
    application_types: list[str] | None = None,
    account_count: int | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "id": identity.id,
        "identity_type": identity.identity_type.value,
        "email": identity.email,
        "display_name": identity.display_name,
        "is_disabled": identity.is_disabled,
        "mfa_enabled": identity.mfa_enabled,
        "is_external": identity.is_external,
        "application_instance_id": identity.application_instance_id,
        "privileged": identity.id in privileged_ids,
        "created_at": identity.created_at.isoformat() if identity.created_at else None,
        "last_active_at": identity.last_active_at.isoformat() if identity.last_active_at else None,
        "last_active_source": identity.last_active_source,
        "worker_type": identity.worker_type,
        "worker_type_source": identity.worker_type_source,
        "department": identity.department,
        "title": identity.title,
        "manager_email": identity.manager_email,
        "disabled_at": identity.disabled_at.isoformat() if identity.disabled_at else None,
        "expires_at": identity.expires_at.isoformat() if identity.expires_at else None,
        "explore_path": (f"/explore?focus={identity.id}&focus_type=identity&direction=out"),
    }
    if application_types is not None:
        payload["application_types"] = application_types
    if account_count is not None:
        payload["account_count"] = account_count
    return payload


@router.get("")
def list_identities(
    identity_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    privileged: bool | None = Query(default=None),
    is_external: bool | None = Query(default=None),
    mfa_enabled: bool | None = Query(default=None),
    worker_type: str | None = Query(
        default=None, description="employee, contractor, vendor_or_partner, guest, service, unknown"
    ),
    application_instance_id: uuid.UUID | None = Query(default=None),
    collapse: bool = Query(
        default=False,
        description="Dedupe cross-app correlated identities. Limit is post-collapse.",
    ),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    page_limit = normalize_limit(limit)
    fetch_limit = page_limit
    if collapse:
        # Over-fetch so post-dedupe pages still fill; cursor stays on raw order.
        fetch_limit = min(max(page_limit * 3, page_limit), MAX_LIMIT)

    stmt = select(Identity).where(Identity.org_id == org.id, is_active(Identity))

    if identity_type is not None:
        try:
            parsed_type = IdentityType(identity_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unknown identity_type '{identity_type}'") from exc
        stmt = stmt.where(Identity.identity_type == parsed_type)

    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Identity.display_name.ilike(pattern), Identity.email.ilike(pattern)))

    if is_external is not None:
        stmt = stmt.where(Identity.is_external.is_(is_external))
    if mfa_enabled is not None:
        stmt = stmt.where(Identity.mfa_enabled.is_(mfa_enabled))
    if worker_type is not None:
        if worker_type not in WORKER_TYPES:
            raise HTTPException(status_code=422, detail=f"Unknown worker_type '{worker_type}'")
        stmt = stmt.where(Identity.worker_type == worker_type)
    if application_instance_id is not None:
        stmt = stmt.where(Identity.application_instance_id == application_instance_id)

    priv_subq = privileged_identity_ids_subquery(org.id)
    if privileged is True:
        stmt = stmt.where(Identity.id.in_(priv_subq))
    elif privileged is False:
        stmt = stmt.where(~Identity.id.in_(priv_subq))

    stmt = apply_keyset(
        stmt,
        sort_column=Identity.created_at,
        id_column=Identity.id,
        cursor=cursor,
        limit=fetch_limit,
    )
    rows = list(db.scalars(stmt).all())

    cluster_meta: dict[uuid.UUID, dict] = {}
    # Collapsed pages are cut on raw order: the cursor points at the last raw
    # row the page consumed, and more exist if any raw row was left over.
    collapsed_next_cursor: str | None = None
    if collapse and rows:
        from kestrel.identities.correlate import collapse_identity_search_hits

        raw = rows[:fetch_limit]  # rows[fetch_limit], if any, is the has-more sentinel
        cluster_meta = collapse_identity_search_hits(db, org_id=org.id, identity_object_ids=[r.id for r in raw])
        seen_reps: set[uuid.UUID] = set()
        collapsed: list[Identity] = []
        by_id = {r.id: r for r in raw}
        consumed = 0
        for row in raw:
            consumed += 1
            meta = cluster_meta.get(row.id)
            rep_id = meta["representative_identity_id"] if meta else row.id
            if rep_id in seen_reps:
                continue
            seen_reps.add(rep_id)
            # The cluster's display name is applied at serialization, not on the ORM row.
            collapsed.append(by_id.get(rep_id, row))
            if len(collapsed) >= page_limit:
                break
        if len(rows) > consumed:
            last_raw = raw[consumed - 1]
            collapsed_next_cursor = encode_cursor(last_raw.created_at, last_raw.id)
        rows = collapsed

    # Privileged flags for the page only (not the whole org).
    page_ids = [r.id for r in rows[:page_limit]]
    privileged_ids: set[uuid.UUID] = set()
    if page_ids:
        privileged_ids = set(
            db.scalars(
                select(Identity.id).where(
                    Identity.org_id == org.id,
                    Identity.id.in_(page_ids),
                    Identity.id.in_(priv_subq),
                )
            ).all()
        )

    def _ser(identity: Identity) -> dict:
        meta = cluster_meta.get(identity.id)
        app_types = list(meta["application_types"]) if meta else None
        account_count = int(meta["member_count"]) if meta else None
        payload = _serialize_identity(
            identity,
            privileged_ids=privileged_ids,
            application_types=app_types,
            account_count=account_count,
        )
        if meta and meta.get("display_name"):
            payload["display_name"] = meta["display_name"]
        return payload

    if collapse:
        return {"items": [_ser(r) for r in rows], "next_cursor": collapsed_next_cursor}
    return build_page(
        rows,
        limit=page_limit,
        sort_attr="created_at",
        serializer=_ser,
    )


@router.get("/correlated")
def list_correlated_identities(
    min_connectors: int = Query(default=2, ge=2, le=20),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Cross-connector identity clusters sharing a normalized email."""
    from kestrel.identities.correlate import correlate_identities_by_email

    clusters = correlate_identities_by_email(db, org_id=org.id, min_connectors=min_connectors)
    return {"items": clusters, "count": len(clusters)}


@router.get("/{identity_id}")
def get_identity(
    identity_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    identity = db.get(Identity, identity_id)
    if identity is None or identity.org_id != org.id or identity.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Identity not found")
    priv_subq = privileged_identity_ids_subquery(org.id)
    is_priv = (
        db.scalar(
            select(Identity.id).where(
                Identity.id == identity.id,
                Identity.id.in_(priv_subq),
            )
        )
        is not None
    )
    return _serialize_identity(identity, privileged_ids={identity.id} if is_priv else set())


@router.get("/{identity_id}/overview")
def identity_overview(
    identity_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Everything the identity detail page shows, in one round trip.

    Composed server-side rather than fetched piecemeal: the page renders as a
    server component, and six sequential API calls is six times the latency
    for a view whose whole point is answering "what does this person have"
    quickly.
    """
    identity = db.get(Identity, identity_id)
    if identity is None or identity.org_id != org.id or identity.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Identity not found")

    from kestrel.db.models.access import Grant, Group, GroupMembership
    from kestrel.db.models.oauth import OAuthGrant
    from kestrel.identities.correlate import identity_cluster_for
    from kestrel.identities.detail import access_preview, enrich_grant, enrich_oauth_grant, identity_app_context
    from kestrel.identities.findings_summary import identity_findings_summary
    from kestrel.identities.risk_factors import identity_risk_factors
    from kestrel.identities.timeline import identity_timeline

    cluster = identity_cluster_for(db, org_id=org.id, identity_id=identity.id)
    cluster_ids = [uuid.UUID(i) for i in cluster["identity_ids"]] if cluster else [identity.id]

    # Access is shown for the whole person, not just the account being viewed:
    # "what can Grace reach" spans her four accounts.
    grants = list(
        db.scalars(
            select(Grant)
            .where(Grant.org_id == org.id, Grant.identity_id.in_(cluster_ids), is_active(Grant))
            .order_by(Grant.first_seen_at.desc())
            .limit(500)
        ).all()
    )
    # execute(), not scalars(): a two-column select through scalars() yields
    # only the Group and the tuple unpack below fails at runtime.
    memberships = list(
        db.execute(
            select(Group, GroupMembership)
            .join(GroupMembership, GroupMembership.group_id == Group.id)
            .where(
                GroupMembership.org_id == org.id,
                GroupMembership.identity_id.in_(cluster_ids),
                is_active(GroupMembership),
                is_active(Group),
            )
            .order_by(Group.name.asc())
            .limit(200)
        ).all()
    )
    oauth_grants = list(
        db.scalars(
            select(OAuthGrant)
            .where(OAuthGrant.org_id == org.id, OAuthGrant.identity_id.in_(cluster_ids), is_active(OAuthGrant))
            .order_by(OAuthGrant.granted_at.desc())
            .limit(200)
        ).all()
    )

    priv_subq = privileged_identity_ids_subquery(org.id)
    privileged_ids = set(
        db.scalars(select(Identity.id).where(Identity.id.in_(cluster_ids), Identity.id.in_(priv_subq))).all()
    )

    return {
        "identity": _serialize_identity(identity, privileged_ids=privileged_ids),
        "application": identity_app_context(db, identity),
        "cluster": cluster,
        "groups": [
            {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "identity_id": membership.identity_id,
            }
            for group, membership in memberships
        ],
        "grants": [enrich_grant(db, grant, fallback_app_instance_id=identity.application_instance_id) for grant in grants],
        "oauth_grants": [enrich_oauth_grant(db, grant, org_id=org.id) for grant in oauth_grants],
        "access_preview": access_preview(db, org_id=org.id, identity_id=identity.id),
        "findings": identity_findings_summary(db, org.id, identity.id),
        "risk_factors": identity_risk_factors(db, org.id, identity.id),
        "timeline": identity_timeline(db, org_id=org.id, identity_id=identity.id, limit=25),
        "explore_path": f"/explore?focus={identity.id}&focus_type=identity&direction=out",
    }


@router.get("/{identity_id}/access")
def identity_access(
    identity_id: uuid.UUID,
    depth: int = Query(default=3, ge=1, le=6),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    identity = db.get(Identity, identity_id)
    if identity is None or identity.org_id != org.id or identity.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity_reachable_access(db, org_id=org.id, identity_id=identity.id, depth=depth)
