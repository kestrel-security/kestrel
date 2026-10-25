# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Peer-group privilege comparison.

Compares each identity's privileged-role count to the **median** among peers
who share a graph ``member_of`` group (not inferred job titles / departments).
Outliers are labeled with the peer group, size, and median — never an opaque
risk score.
"""

from __future__ import annotations

import statistics
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from kestrel.db.models.access import Group, Role
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity

DEFAULT_MIN_PEER_GROUP_SIZE = 3


def _privilege_counts(db: Session, org_id: uuid.UUID) -> dict[uuid.UUID, list[str]]:
    """Map identity_id → sorted unique privileged role names."""
    identity_node = aliased(GraphNode)
    role_node = aliased(GraphNode)
    rows = db.execute(
        select(Identity.id, Role.name)
        .select_from(Identity)
        .join(identity_node, identity_node.object_id == Identity.id)
        .join(GraphEdge, GraphEdge.source_node_id == identity_node.id)
        .join(role_node, role_node.id == GraphEdge.target_node_id)
        .join(Role, Role.id == role_node.object_id)
        .where(
            Identity.org_id == org_id,
            identity_node.org_id == org_id,
            identity_node.node_type == GraphNodeType.IDENTITY,
            GraphEdge.org_id == org_id,
            GraphEdge.edge_type == GraphEdgeType.ASSIGNED_ROLE,
            role_node.node_type == GraphNodeType.ROLE,
            Role.is_privileged.is_(True),
            Role.org_id == org_id,
        )
    ).all()
    out: dict[uuid.UUID, list[str]] = defaultdict(list)
    for identity_id, role_name in rows:
        if role_name not in out[identity_id]:
            out[identity_id].append(role_name)
    for identity_id in out:
        out[identity_id] = sorted(out[identity_id])
    return dict(out)


def _group_memberships(db: Session, org_id: uuid.UUID) -> tuple[dict[uuid.UUID, list[uuid.UUID]], dict[uuid.UUID, str]]:
    """Return (group_id → member identity ids, group_id → name)."""
    identity_node = aliased(GraphNode)
    group_node = aliased(GraphNode)
    rows = db.execute(
        select(Identity.id, Group.id, Group.name)
        .select_from(Identity)
        .join(identity_node, identity_node.object_id == Identity.id)
        .join(GraphEdge, GraphEdge.source_node_id == identity_node.id)
        .join(group_node, group_node.id == GraphEdge.target_node_id)
        .join(Group, Group.id == group_node.object_id)
        .where(
            Identity.org_id == org_id,
            identity_node.org_id == org_id,
            identity_node.node_type == GraphNodeType.IDENTITY,
            GraphEdge.org_id == org_id,
            GraphEdge.edge_type == GraphEdgeType.MEMBER_OF,
            group_node.node_type == GraphNodeType.GROUP,
            Group.org_id == org_id,
        )
    ).all()
    members: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    names: dict[uuid.UUID, str] = {}
    for identity_id, group_id, group_name in rows:
        if identity_id not in members[group_id]:
            members[group_id].append(identity_id)
        names[group_id] = group_name
    return dict(members), names


def build_peer_privilege_items(
    db: Session,
    org_id: uuid.UUID,
    *,
    min_peer_group_size: int = DEFAULT_MIN_PEER_GROUP_SIZE,
) -> list[dict[str, Any]]:
    """One row per outlier identity with explained peer group + median."""
    min_size = max(2, min_peer_group_size)
    privilege_roles = _privilege_counts(db, org_id)
    group_members, group_names = _group_memberships(db, org_id)

    # Best outlier match per identity: largest excess over median.
    best: dict[uuid.UUID, dict[str, Any]] = {}

    for group_id, member_ids in group_members.items():
        if len(member_ids) < min_size:
            continue
        counts = [len(privilege_roles.get(mid, [])) for mid in member_ids]
        median = float(statistics.median(counts))
        for mid in member_ids:
            priv_count = len(privilege_roles.get(mid, []))
            if priv_count <= median:
                continue
            excess = priv_count - median
            prev = best.get(mid)
            if prev is not None and excess <= float(prev["excess_over_median"]):
                continue
            best[mid] = {
                "identity_id": mid,
                "privileged_role_count": priv_count,
                "privileged_roles": list(privilege_roles.get(mid, [])),
                "peer_group_type": "group",
                "peer_group_id": group_id,
                "peer_group_name": group_names.get(group_id) or str(group_id),
                "peer_group_size": len(member_ids),
                "peer_median_privileged_roles": median,
                "excess_over_median": excess,
            }

    if not best:
        return []

    identities = {
        i.id: i for i in db.scalars(select(Identity).where(Identity.org_id == org_id, Identity.id.in_(best.keys()))).all()
    }
    app_ids = {i.application_instance_id for i in identities.values() if i.application_instance_id}
    instances = (
        {
            inst.id: inst
            for inst in db.scalars(
                select(ApplicationInstance).where(
                    ApplicationInstance.org_id == org_id,
                    ApplicationInstance.id.in_(app_ids),
                )
            ).all()
        }
        if app_ids
        else {}
    )
    apps = (
        {
            a.id: a
            for a in db.scalars(
                select(Application).where(
                    Application.org_id == org_id,
                    Application.id.in_({inst.application_id for inst in instances.values()}),
                )
            ).all()
        }
        if instances
        else {}
    )

    items: list[dict[str, Any]] = []
    for identity_id, row in best.items():
        identity = identities.get(identity_id)
        if identity is None:
            continue
        inst = instances.get(identity.application_instance_id) if identity.application_instance_id else None
        app = apps.get(inst.application_id) if inst else None
        items.append(
            {
                **row,
                "display_name": identity.display_name,
                "email": identity.email,
                "application_instance_id": identity.application_instance_id,
                "application_display_name": inst.display_name if inst else None,
                "application_type": app.application_type.value if app else None,
                "detail_path": f"/identities/{identity_id}",
                "findings_list_path": f"/findings?status=open&subject_id={identity_id}",
                "explanation": (
                    f"{row['privileged_role_count']} privileged role(s) vs median "
                    f"{row['peer_median_privileged_roles']:g} among {row['peer_group_size']} "
                    f"members of graph group “{row['peer_group_name']}” "
                    f"(shared member_of — not job title)."
                ),
            }
        )

    items.sort(
        key=lambda i: (
            -float(i["excess_over_median"]),
            -int(i["privileged_role_count"]),
            (i.get("email") or "").lower(),
            str(i["identity_id"]),
        )
    )
    return items
