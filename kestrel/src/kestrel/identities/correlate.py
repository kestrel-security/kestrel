# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Cross-connector identity correlation.

Identities remain per-application-instance rows. This module builds a
correlation view so operators can answer “who is this person across SaaS?”
without merging rows (FK rewrite remains a later product decision).

Explore uses the same heuristics at read time: high-confidence email match,
plus medium-confidence unique display-name match (same rule as the graph identity collapse).
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kestrel.db.base import is_active
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.identity import Identity

# Prefer IdP accounts as the Explore search representative.
_IDP_APP_TYPES = frozenset(
    {
        ApplicationType.OKTA.value,
        ApplicationType.GOOGLE_WORKSPACE.value,
    }
)

_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)
_WS_RE = re.compile(r"\s+")


def _norm_email(email: str | None) -> str | None:
    if not email or not isinstance(email, str):
        return None
    value = email.strip().casefold()
    return value or None


def _display_name_key(name: str | None) -> str | None:
    """Normalize display names for cross-app duplicate matching."""
    if name is None:
        return None
    cleaned = _PUNCT_RE.sub("", name.strip().lower())
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    return cleaned or None


def _app_type_str(application_type: Any) -> str:
    return application_type.value if hasattr(application_type, "value") else str(application_type)


def _identity_row_dicts(
    session: Session, *, org_id: uuid.UUID, identity_ids: list[uuid.UUID] | None = None
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Identity.id,
            Identity.email,
            Identity.display_name,
            Identity.is_disabled,
            Identity.mfa_enabled,
            Application.application_type,
            ApplicationInstance.display_name,
            ApplicationInstance.id,
        )
        .join(ApplicationInstance, ApplicationInstance.id == Identity.application_instance_id)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(
            Identity.org_id == org_id,
            is_active(Identity),
            *([Identity.id.in_(identity_ids)] if identity_ids is not None else []),
        )
    ).all()

    out: list[dict[str, Any]] = []
    for (
        identity_id,
        email,
        display_name,
        is_disabled,
        mfa_enabled,
        application_type,
        instance_display_name,
        instance_id,
    ) in rows:
        out.append(
            {
                "identity_id": identity_id,
                "email": email,
                "display_name": display_name,
                "is_disabled": bool(is_disabled),
                "mfa_enabled": mfa_enabled,
                "application_type": _app_type_str(application_type),
                "application_instance_id": instance_id,
                "application_instance_display_name": instance_display_name,
            }
        )
    return out


def _unique_display_name_keys(rows: list[dict[str, Any]]) -> set[str]:
    """Display-name keys safe for medium-confidence cross-app linking.

    Requires a multi-token name (\"Grace Hopper\", not \"Alex\" / \"alice\") and
    at most one identity with that key per application instance. That merges one
    person's accounts across two applications even when the emails differ,
    while avoiding first-name-only collisions.
    """
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = _display_name_key(row.get("display_name"))
        if key:
            by_key[key].append(row)

    unique: set[str] = set()
    for key, members in by_key.items():
        if " " not in key:
            continue
        per_instance: dict[Any, int] = defaultdict(int)
        for m in members:
            per_instance[m["application_instance_id"]] += 1
        if any(count > 1 for count in per_instance.values()):
            continue
        unique.add(key)
    return unique


def _build_clusters(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Union-find clusters: email edges + unique-display-name edges."""
    if not rows:
        return []

    unique_names = _unique_display_name_keys(rows)
    parent: dict[uuid.UUID, uuid.UUID] = {r["identity_id"]: r["identity_id"] for r in rows}

    def find(x: uuid.UUID) -> uuid.UUID:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: uuid.UUID, b: uuid.UUID) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    by_email: dict[str, list[uuid.UUID]] = defaultdict(list)
    by_name: dict[str, list[uuid.UUID]] = defaultdict(list)
    for row in rows:
        eid = row["identity_id"]
        email_key = _norm_email(row.get("email"))
        if email_key:
            by_email[email_key].append(eid)
        name_key = _display_name_key(row.get("display_name"))
        if name_key and name_key in unique_names:
            by_name[name_key].append(eid)

    for ids in by_email.values():
        for other in ids[1:]:
            union(ids[0], other)
    for ids in by_name.values():
        for other in ids[1:]:
            union(ids[0], other)

    buckets: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[find(row["identity_id"])].append(row)
    return list(buckets.values())


def _match_kind_for(account: dict[str, Any], cluster: list[dict[str, Any]]) -> str:
    email_key = _norm_email(account.get("email"))
    if email_key and any(
        _norm_email(m.get("email")) == email_key and m["identity_id"] != account["identity_id"] for m in cluster
    ):
        return "email"
    name_key = _display_name_key(account.get("display_name"))
    if name_key and any(
        _display_name_key(m.get("display_name")) == name_key and m["identity_id"] != account["identity_id"] for m in cluster
    ):
        return "display_name"
    return "self"


def _representative(cluster: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer IdP account, else stable sort by application_type then id."""

    def sort_key(row: dict[str, Any]) -> tuple:
        app = row["application_type"]
        idp_rank = 0 if app in _IDP_APP_TYPES else 1
        return (idp_rank, app, str(row["identity_id"]))

    return sorted(cluster, key=sort_key)[0]


def _account_payload(row: dict[str, Any], *, match_kind: str) -> dict[str, Any]:
    return {
        "identity_id": str(row["identity_id"]),
        "application_type": row["application_type"],
        "application_display_name": row["application_instance_display_name"],
        "email": row.get("email"),
        "display_name": row.get("display_name"),
        "mfa_enabled": row.get("mfa_enabled"),
        "is_disabled": bool(row.get("is_disabled")),
        "match_kind": match_kind,
    }


def rebuild_identity_links(session: Session, *, org_id: uuid.UUID) -> int:
    """Recompute the org's correlation clusters into ``identity_links``.

    Called at the end of every complete sync. Wholesale replace rather than a
    diff: clusters move as a unit when an email appears or an account leaves,
    and the table is a derived read model with no history of its own.

    Returns the number of rows written.
    """
    from kestrel.db.models.identity_link import IdentityLink

    rows = _identity_row_dicts(session, org_id=org_id)
    session.execute(delete(IdentityLink).where(IdentityLink.org_id == org_id))
    if not rows:
        return 0

    now = datetime.now(UTC)
    written = 0
    for cluster in _build_clusters(rows):
        rep = _representative(cluster)
        app_types = sorted({m["application_type"] for m in cluster})
        for member in cluster:
            session.add(
                IdentityLink(
                    id=uuid.uuid4(),
                    org_id=org_id,
                    identity_id=member["identity_id"],
                    cluster_key=str(rep["identity_id"]),
                    representative_identity_id=rep["identity_id"],
                    match_kind=_match_kind_for(member, cluster),
                    member_count=len(cluster),
                    application_types=app_types,
                    computed_at=now,
                )
            )
            written += 1
    session.flush()
    return written


def _linked_identity_ids(session: Session, *, org_id: uuid.UUID, identity_id: uuid.UUID) -> list[uuid.UUID] | None:
    """Cluster member ids from ``identity_links``, or None when not materialized.

    None means "the table has nothing for this identity" -- either the org has
    never synced or the row predates the rebuild -- and every caller falls back
    to computing the cluster in memory rather than reporting a singleton.
    """
    from kestrel.db.models.identity_link import IdentityLink

    cluster_key = session.scalar(
        select(IdentityLink.cluster_key).where(IdentityLink.org_id == org_id, IdentityLink.identity_id == identity_id)
    )
    if cluster_key is None:
        return None
    return list(
        session.scalars(
            select(IdentityLink.identity_id).where(IdentityLink.org_id == org_id, IdentityLink.cluster_key == cluster_key)
        ).all()
    )


def _materialized_clusters(
    session: Session, *, org_id: uuid.UUID, identity_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]] | None:
    """Clusters for the given identities, read from ``identity_links``.

    None when any requested identity has no link row, so the caller recomputes
    rather than silently reporting a person as a singleton.
    """
    from kestrel.db.models.identity_link import IdentityLink

    if not identity_ids:
        return {}
    keys: dict[uuid.UUID, str] = {
        row[0]: row[1]
        for row in session.execute(
            select(IdentityLink.identity_id, IdentityLink.cluster_key).where(
                IdentityLink.org_id == org_id, IdentityLink.identity_id.in_(identity_ids)
            )
        ).all()
    }
    if not keys:
        return None
    wanted_keys = set(keys.values())
    members = list(
        session.scalars(
            select(IdentityLink.identity_id).where(IdentityLink.org_id == org_id, IdentityLink.cluster_key.in_(wanted_keys))
        ).all()
    )
    rows = _identity_row_dicts(session, org_id=org_id, identity_ids=members)
    key_by_id: dict[uuid.UUID, str] = {
        row[0]: row[1]
        for row in session.execute(
            select(IdentityLink.identity_id, IdentityLink.cluster_key).where(
                IdentityLink.org_id == org_id, IdentityLink.identity_id.in_(members)
            )
        ).all()
    }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cluster_key = key_by_id.get(row["identity_id"])
        if cluster_key:
            grouped[cluster_key].append(row)
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for cluster_members in grouped.values():
        for member in cluster_members:
            out[member["identity_id"]] = cluster_members
    return out


def identity_cluster_for(
    session: Session,
    *,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
) -> dict[str, Any] | None:
    """Return the correlation cluster containing ``identity_id``, or None if missing.

    Singleton clusters (one account) are still returned so Explore can render
    a consistent ``accounts`` list.
    """
    linked_ids = _linked_identity_ids(session, org_id=org_id, identity_id=identity_id)
    if linked_ids is not None:
        # Materialized: load only the cluster's own accounts.
        rows = _identity_row_dicts(session, org_id=org_id, identity_ids=linked_ids)
        by_id = {r["identity_id"]: r for r in rows}
        if identity_id not in by_id:
            return None
        cluster = rows
    else:
        rows = _identity_row_dicts(session, org_id=org_id)
        by_id = {r["identity_id"]: r for r in rows}
        if identity_id not in by_id:
            return None

        clusters = _build_clusters(rows)
        found: list[dict[str, Any]] | None = None
        for members in clusters:
            if any(m["identity_id"] == identity_id for m in members):
                found = members
                break
        cluster = found if found is not None else [by_id[identity_id]]

    rep = _representative(cluster)
    accounts = [
        _account_payload(m, match_kind=_match_kind_for(m, cluster))
        for m in sorted(cluster, key=lambda r: (r["application_type"], str(r["identity_id"])))
    ]
    app_types = sorted({m["application_type"] for m in cluster})
    return {
        "representative_identity_id": str(rep["identity_id"]),
        "identity_ids": [str(m["identity_id"]) for m in cluster],
        "member_count": len(cluster),
        "application_types": app_types,
        "accounts": accounts,
        "display_name": rep.get("display_name") or by_id[identity_id].get("display_name"),
        "email": rep.get("email") or by_id[identity_id].get("email"),
    }


def cluster_identity_ids(
    session: Session,
    *,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
) -> list[uuid.UUID]:
    """UUID list of identity PKs in the same cluster (at least ``identity_id``)."""
    cluster = identity_cluster_for(session, org_id=org_id, identity_id=identity_id)
    if cluster is None:
        return [identity_id]
    return [uuid.UUID(i) for i in cluster["identity_ids"]]


def collapse_identity_search_hits(
    session: Session,
    *,
    org_id: uuid.UUID,
    identity_object_ids: list[uuid.UUID],
) -> dict[uuid.UUID, dict[str, Any]]:
    """Map each identity object_id → cluster metadata for search collapse.

    Keys are every input id; values share the same cluster dict for siblings.
    Missing identities are omitted.
    """
    cluster_by_id = _materialized_clusters(session, org_id=org_id, identity_ids=identity_object_ids)
    if cluster_by_id is not None:
        by_id = {oid: row for rows in cluster_by_id.values() for row in rows for oid in [row["identity_id"]]}
    else:
        rows = _identity_row_dicts(session, org_id=org_id)
        by_id = {r["identity_id"]: r for r in rows}
        clusters = _build_clusters(rows)
        cluster_by_id = {}
        for members in clusters:
            for m in members:
                cluster_by_id[m["identity_id"]] = members

    out: dict[uuid.UUID, dict[str, Any]] = {}
    for oid in identity_object_ids:
        cluster_members = cluster_by_id.get(oid)
        if cluster_members is None:
            if oid not in by_id:
                continue
            cluster_members = [by_id[oid]]
        rep = _representative(cluster_members)
        app_types = sorted({m["application_type"] for m in cluster_members})
        meta = {
            "representative_identity_id": rep["identity_id"],
            "member_count": len(cluster_members),
            "application_types": app_types,
            "display_name": rep.get("display_name"),
            "email": rep.get("email"),
            "identity_ids": [m["identity_id"] for m in cluster_members],
        }
        for m in cluster_members:
            out[m["identity_id"]] = meta
        # Ensure requested id is keyed even if somehow missing from members.
        out[oid] = meta
    return out


def correlate_identities_by_email(
    session: Session,
    *,
    org_id: uuid.UUID,
    min_connectors: int = 2,
) -> list[dict[str, Any]]:
    """Return clusters of identities that share an email across connectors.

    Each cluster includes member identity ids, emails, display names, and
    application types — enough for Explore to show cross-app admin.
    """
    rows = session.execute(
        select(
            Identity.id,
            Identity.email,
            Identity.display_name,
            Identity.is_disabled,
            Application.application_type,
            ApplicationInstance.display_name,
            ApplicationInstance.id,
        )
        .join(ApplicationInstance, ApplicationInstance.id == Identity.application_instance_id)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(Identity.org_id == org_id, is_active(Identity))
    ).all()

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (
        identity_id,
        email,
        display_name,
        is_disabled,
        application_type,
        instance_display_name,
        instance_id,
    ) in rows:
        key = _norm_email(email)
        if not key:
            continue
        app_type = _app_type_str(application_type)
        buckets[key].append(
            {
                "identity_id": str(identity_id),
                "email": email,
                "display_name": display_name,
                "is_disabled": bool(is_disabled),
                "application_type": app_type,
                "application_instance_id": str(instance_id),
                "application_instance_display_name": instance_display_name,
            }
        )

    clusters: list[dict[str, Any]] = []
    for email, members in sorted(buckets.items()):
        app_types = sorted({m["application_type"] for m in members})
        instance_ids = {m["application_instance_id"] for m in members}
        if len(app_types) < min_connectors and len(instance_ids) < min_connectors:
            continue
        clusters.append(
            {
                "email": email,
                "member_count": len(members),
                "application_types": app_types,
                "members": members,
            }
        )
    clusters.sort(key=lambda c: (-c["member_count"], c["email"]))
    return clusters
