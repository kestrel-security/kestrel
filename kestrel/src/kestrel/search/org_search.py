# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-scoped entity search for the command palette — people, findings, and policies."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kestrel.db.base import is_active
from kestrel.db.models.finding import Finding
from kestrel.db.models.identity import Identity
from kestrel.db.models.policy import Policy

DEFAULT_LIMIT_PER_TYPE = 8
MAX_LIMIT_PER_TYPE = 20
MIN_QUERY_LEN = 1
MAX_QUERY_LEN = 200

GROUP_ORDER = ("identity", "finding", "policy")


class SearchError(ValueError):
    """Invalid search parameters."""


def _item(*, id: uuid.UUID | str, label: str, subtitle: str | None, href: str) -> dict[str, Any]:
    return {
        "id": str(id),
        "label": label,
        "subtitle": subtitle,
        "href": href,
    }


def org_search(
    db: Session,
    *,
    org_id: uuid.UUID,
    query: str,
    limit_per_type: int = DEFAULT_LIMIT_PER_TYPE,
) -> dict[str, Any]:
    """Return grouped search hits for ``query`` within ``org_id``."""
    q = (query or "").strip()
    if len(q) > MAX_QUERY_LEN:
        raise SearchError(f"q must be at most {MAX_QUERY_LEN} characters")
    if limit_per_type < 1 or limit_per_type > MAX_LIMIT_PER_TYPE:
        raise SearchError(f"limit_per_type must be 1–{MAX_LIMIT_PER_TYPE}")

    if len(q) < MIN_QUERY_LEN:
        return {"query": q, "groups": [{"type": t, "items": []} for t in GROUP_ORDER]}

    term = f"%{q}%"
    groups: list[dict[str, Any]] = []

    # People first: "find Grace" is the most common thing anyone types, and
    # correlated accounts collapse so one person is one hit rather than four.
    identities = list(
        db.scalars(
            select(Identity)
            .where(
                Identity.org_id == org_id,
                is_active(Identity),
                or_(Identity.display_name.ilike(term), Identity.email.ilike(term)),
            )
            .order_by(Identity.display_name.asc(), Identity.id.asc())
            .limit(limit_per_type * 4)
        ).all()
    )
    identity_items: list[dict[str, Any]] = []
    if identities:
        from kestrel.identities.correlate import collapse_identity_search_hits

        clusters = collapse_identity_search_hits(db, org_id=org_id, identity_object_ids=[i.id for i in identities])
        seen_representatives: set[Any] = set()
        for row in identities:
            meta = clusters.get(row.id)
            representative = meta["representative_identity_id"] if meta else row.id
            if representative in seen_representatives:
                continue
            seen_representatives.add(representative)
            application_types = list(meta["application_types"]) if meta else []
            subtitle = row.email or ""
            if len(application_types) > 1:
                subtitle = (
                    f"{subtitle} · {len(application_types)} applications"
                    if subtitle
                    else (f"{len(application_types)} applications")
                )
            identity_items.append(
                _item(
                    id=representative,
                    label=(meta["display_name"] if meta and meta.get("display_name") else row.display_name)
                    or row.email
                    or str(row.id),
                    subtitle=subtitle or None,
                    href=f"/identities/{representative}",
                )
            )
            if len(identity_items) >= limit_per_type:
                break
    groups.append({"type": "identity", "items": identity_items})

    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.org_id == org_id, Finding.title.ilike(term))
            .order_by(Finding.last_seen_at.desc())
            .limit(limit_per_type)
        ).all()
    )
    groups.append(
        {
            "type": "finding",
            "items": [
                _item(
                    id=row.id,
                    label=row.title,
                    subtitle=row.severity.value if row.severity else None,
                    href=f"/findings/{row.id}",
                )
                for row in findings
            ],
        }
    )

    policies = list(
        db.scalars(
            select(Policy)
            .where(
                Policy.org_id == org_id,
                or_(Policy.title.ilike(term), Policy.slug.ilike(term)),
            )
            .order_by(Policy.updated_at.desc())
            .limit(limit_per_type)
        ).all()
    )
    groups.append(
        {
            "type": "policy",
            "items": [
                _item(
                    id=row.id,
                    label=row.title or row.slug,
                    subtitle=row.slug,
                    href=f"/policies/{row.id}",
                )
                for row in policies
            ],
        }
    )

    return {"query": q, "groups": groups}
