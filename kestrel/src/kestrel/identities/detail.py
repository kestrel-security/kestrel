# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identity detail enrichment: resolve grant/OAuth labels and app context.

Keeps the identities API router from re-implementing Resource/Role/OAuth
lookups used by the Identity Explorer detail page.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.access import Grant, Group, Role
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.graph_edge import GraphNode, GraphNodeType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant
from kestrel.db.models.resource import Resource
from kestrel.graph.models import GraphNodeRef
from kestrel.graph.queries import reachable_nodes

# Compact graph preview on identity detail — UI deep-links to /graph for more.
ACCESS_PREVIEW_LIMIT = 12


def _app_context(db: Session, application_instance_id: uuid.UUID | None) -> dict:
    if application_instance_id is None:
        return {
            "application_instance_id": None,
            "application_instance_display_name": None,
            "application_type": None,
        }
    instance = db.get(ApplicationInstance, application_instance_id)
    if instance is None:
        return {
            "application_instance_id": application_instance_id,
            "application_instance_display_name": None,
            "application_type": None,
        }
    application = db.get(Application, instance.application_id)
    return {
        "application_instance_id": instance.id,
        "application_instance_display_name": instance.display_name,
        "application_type": application.application_type.value if application else None,
    }


def identity_app_context(db: Session, identity: Identity) -> dict:
    return _app_context(db, identity.application_instance_id)


def enrich_grant(db: Session, grant: Grant, *, fallback_app_instance_id: uuid.UUID | None) -> dict:
    """Resolve resource/role/group labels and app context for one grant row.

    The application comes from the resource, then the role, then the account
    holding the grant. ``fallback_app_instance_id`` is a last resort only: the
    identity page lists grants for every account in a correlated person, so
    the account being viewed is often not the one the grant belongs to.
    """
    resource_name = None
    resource_type = None
    role_name = None
    role_is_privileged = None
    source_group_name = None
    app_instance_id: uuid.UUID | None = None

    if grant.resource_id is not None:
        resource = db.get(Resource, grant.resource_id)
        if resource is not None and resource.org_id == grant.org_id:
            resource_name = resource.name
            resource_type = resource.resource_type.value
            app_instance_id = resource.application_instance_id

    if grant.role_id is not None:
        role = db.get(Role, grant.role_id)
        if role is not None and role.org_id == grant.org_id:
            role_name = role.name
            role_is_privileged = role.is_privileged
            if app_instance_id is None:
                app_instance_id = role.application_instance_id

    if app_instance_id is None and grant.identity_id is not None:
        holder = db.get(Identity, grant.identity_id)
        if holder is not None and holder.org_id == grant.org_id:
            app_instance_id = holder.application_instance_id

    if app_instance_id is None:
        app_instance_id = fallback_app_instance_id

    if grant.source_group_id is not None:
        group = db.get(Group, grant.source_group_id)
        if group is not None and group.org_id == grant.org_id:
            source_group_name = group.name

    return {
        "id": grant.id,
        "granted_via": grant.granted_via.value,
        "permission_level": grant.permission_level,
        "resource_id": grant.resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "role_id": grant.role_id,
        "role_name": role_name,
        "role_is_privileged": role_is_privileged,
        "source_group_id": grant.source_group_id,
        "source_group_name": source_group_name,
        **_app_context(db, app_instance_id),
    }


def enrich_oauth_grant(db: Session, grant: OAuthGrant, *, org_id: uuid.UUID) -> dict:
    app = db.get(OAuthApplication, grant.oauth_application_id)
    name = None
    publisher = None
    app_ctx: dict = {
        "application_instance_id": None,
        "application_instance_display_name": None,
        "application_type": None,
    }
    if app is not None and app.org_id == org_id:
        name = app.name
        publisher = app.publisher
        app_ctx = _app_context(db, app.application_instance_id)
    return {
        "id": grant.id,
        "oauth_application_id": grant.oauth_application_id,
        "oauth_application_name": name,
        "publisher": publisher,
        "granted_at": grant.granted_at.isoformat(),
        "last_used_at": grant.last_used_at.isoformat() if grant.last_used_at else None,
        **app_ctx,
    }


def _node_type_str(node_type: GraphNodeType | str) -> str:
    return node_type.value if isinstance(node_type, GraphNodeType) else str(node_type)


def serialize_reachable_node(n: GraphNodeRef) -> dict:
    """Flat node dict shared by access preview and `/identities/{id}/access`."""
    node_type = getattr(n, "node_type", None)
    return {
        "id": n.id,
        "node_type": _node_type_str(node_type) if node_type is not None else "",
        "object_id": n.object_id,
        "label": n.label,
        "properties": getattr(n, "properties", None) or {},
    }


def group_reachable_by_type(nodes: list[dict]) -> list[dict]:
    """Group serialized reachable nodes by `node_type` (largest groups first)."""
    by_type: dict[str, list[dict]] = {}
    for node in nodes:
        by_type.setdefault(str(node.get("node_type") or "unknown"), []).append(node)
    return [
        {"node_type": node_type, "count": len(items), "nodes": items}
        for node_type, items in sorted(by_type.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]


def identity_reachable_access(
    db: Session,
    *,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
    depth: int = 3,
) -> dict:
    """Full flatten + group-by-type reachability for Identity Explorer."""
    node = db.scalars(
        select(GraphNode).where(
            GraphNode.org_id == org_id,
            GraphNode.node_type == GraphNodeType.IDENTITY,
            GraphNode.object_id == identity_id,
        )
    ).one_or_none()
    if node is None:
        return {"depth": depth, "total": 0, "reachable": [], "groups": []}

    reachable = reachable_nodes(db, org_id=org_id, start_node_id=node.id, max_depth=depth)
    serialized = [serialize_reachable_node(n) for n in reachable]
    return {
        "depth": depth,
        "total": len(serialized),
        "reachable": serialized,
        "groups": group_reachable_by_type(serialized),
    }


def access_preview(
    db: Session,
    *,
    org_id: uuid.UUID,
    identity_id: uuid.UUID,
    depth: int = 2,
    limit: int = ACCESS_PREVIEW_LIMIT,
) -> dict:
    """Compact reachability sample for identity detail; full panel uses /access."""
    full = identity_reachable_access(db, org_id=org_id, identity_id=identity_id, depth=depth)
    others = full["reachable"]
    total = len(others)
    sample = others[:limit]
    # Preview omits properties to keep the detail payload lean.
    lean = [{"id": n["id"], "node_type": n["node_type"], "object_id": n["object_id"], "label": n["label"]} for n in sample]
    return {
        "reachable": lean,
        "truncated": total > limit,
        "total": total,
    }
