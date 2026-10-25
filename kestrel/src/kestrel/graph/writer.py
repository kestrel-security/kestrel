# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Upserts the graph_nodes/graph_edges read-model from normalized objects.

This is a derived projection, not a source of truth (see ADR-0003) -- it is
rebuilt incrementally on every sync from the NormalizedObjects and the
UpsertContext id maps that kestrel.sync.upsert's entity pass already produced.
Run node upserts before edge upserts: edges need every referenced node's
graph_node_id to already exist.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.connector import ConnectorRun
from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.sync.upsert import _MODEL_BY_KIND, APPEND_ONLY_KINDS, UpsertContext, _any_uuid

_KIND_TO_NODE_TYPE: dict[str, GraphNodeType] = {
    "identity": GraphNodeType.IDENTITY,
    "group": GraphNodeType.GROUP,
    "role": GraphNodeType.ROLE,
    "resource": GraphNodeType.RESOURCE,
    "permission": GraphNodeType.PERMISSION,
    "oauth_application": GraphNodeType.OAUTH_APPLICATION,
    "setting": GraphNodeType.SETTING,
}


def _label(obj: NormalizedObject) -> str:
    return obj.attributes.get("display_name") or obj.attributes.get("name") or obj.attributes.get("label") or obj.provider_id


def _json_safe_properties(attrs: dict) -> dict:
    """GraphNode.properties is JSONB — coerce datetimes to ISO strings."""
    safe: dict = {}
    for key, value in attrs.items():
        if isinstance(value, datetime):
            safe[key] = value.isoformat()
        else:
            safe[key] = value
    return safe


def _app_provenance(session: Session, ctx: UpsertContext) -> dict[str, str]:
    """Stamp application_type + instance display name for Explore captions."""
    row = session.execute(
        select(Application.application_type, ApplicationInstance.display_name)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(
            ApplicationInstance.id == ctx.application_instance_id,
            ApplicationInstance.org_id == ctx.org_id,
        )
    ).one_or_none()
    if row is None:
        return {}
    application_type, display_name = row
    app_type = application_type.value if hasattr(application_type, "value") else str(application_type)
    out: dict[str, str] = {"application_type": app_type}
    if display_name:
        out["application_instance_display_name"] = display_name
    return out


def upsert_nodes(session: Session, objects: list[NormalizedObject], ctx: UpsertContext) -> dict[str, dict[str, uuid.UUID]]:
    """Returns {kind: {provider_id: graph_node_id}}, used by upsert_edges to
    resolve relationship source_ref/target_ref."""
    node_id_maps: dict[str, dict[str, uuid.UUID]] = {kind: {} for kind in _KIND_TO_NODE_TYPE}
    provenance = _app_provenance(session, ctx)

    # Existing nodes, one query per node type, keyed by (type, object id).
    # Nodes added below join the map so a repeated object updates its node.
    object_ids_by_type: dict[GraphNodeType, set[uuid.UUID]] = {}
    for obj in objects:
        if obj.kind in _KIND_TO_NODE_TYPE:
            object_ids_by_type.setdefault(_KIND_TO_NODE_TYPE[obj.kind], set()).add(ctx.id_maps[obj.kind][obj.provider_id])
    nodes: dict[tuple[GraphNodeType, uuid.UUID], GraphNode] = {}
    for node_type, object_ids in object_ids_by_type.items():
        for found in session.scalars(
            select(GraphNode).where(
                GraphNode.org_id == ctx.org_id,
                GraphNode.node_type == node_type,
                _any_uuid(GraphNode.object_id, object_ids),
            )
        ).all():
            nodes.setdefault((node_type, found.object_id), found)

    for obj in objects:
        if obj.kind not in _KIND_TO_NODE_TYPE:
            continue
        node_type = _KIND_TO_NODE_TYPE[obj.kind]
        object_id = ctx.id_maps[obj.kind][obj.provider_id]

        existing = nodes.get((node_type, object_id))

        label = _label(obj)
        props = _json_safe_properties(obj.attributes)
        props.update(provenance)
        if existing is None:
            node = GraphNode(
                id=uuid.uuid4(),
                org_id=ctx.org_id,
                node_type=node_type,
                object_id=object_id,
                label=label,
                properties=props,
            )
            session.add(node)
            nodes[(node_type, object_id)] = node
        else:
            existing.label = label
            existing.properties = props
            node = existing

        node_id_maps[obj.kind][obj.provider_id] = node.id

    # Edges reference these rows by id; write them before upsert_edges runs.
    session.flush()
    return node_id_maps


def upsert_edges(
    session: Session,
    objects: list[NormalizedObject],
    ctx: UpsertContext,
    node_id_maps: dict[str, dict[str, uuid.UUID]],
) -> None:
    now = datetime.now(UTC)

    # Relationships reference entities by provider_id without a "kind" tag,
    # so ids must be unique across kinds within a connector's data for this
    # flattened lookup to resolve correctly. True for GitHub's globally
    # unique object ids; a connector where kinds share an id space would
    # need ids namespaced by kind here instead.
    flat_node_ids: dict[str, uuid.UUID] = {}
    for per_kind in node_id_maps.values():
        flat_node_ids.update(per_kind)

    # Deduplicate within this batch: pending session.add() rows are invisible
    # to SELECT until flush, so identical relationships (common when Slack
    # org role assignments repeat per workspace entity) would UniqueViolation.
    seen_keys: set[tuple[uuid.UUID, uuid.UUID, GraphEdgeType, AccessPath | None]] = set()

    # Existing edges leaving any node this run could draw from, one query,
    # grouped by the full key (duplicates kept together so they can be
    # collapsed below, as the per-edge lookup used to).
    source_ids = {
        source_id
        for obj in objects
        for rel in obj.relationships
        if (source_id := flat_node_ids.get(rel.source_ref)) is not None
    }
    existing_edges: dict[tuple[uuid.UUID, uuid.UUID, GraphEdgeType, AccessPath | None], list[GraphEdge]] = {}
    if source_ids:
        for found in session.scalars(
            select(GraphEdge)
            .where(GraphEdge.org_id == ctx.org_id, _any_uuid(GraphEdge.source_node_id, source_ids))
            .order_by(GraphEdge.id)
        ).all():
            key = (found.source_node_id, found.target_node_id, found.edge_type, found.access_path)
            existing_edges.setdefault(key, []).append(found)

    for obj in objects:
        for rel in obj.relationships:
            source_node_id = flat_node_ids.get(rel.source_ref)
            target_node_id = flat_node_ids.get(rel.target_ref)
            if source_node_id is None or target_node_id is None:
                # Referenced entity wasn't part of this run's normalized set
                # (e.g. a partial/incremental sync) -- skip rather than fail
                # the whole run; a future run covering both ends completes it.
                continue

            edge_type = GraphEdgeType(rel.edge_type)
            access_path = AccessPath(rel.access_path) if rel.access_path else None
            batch_key = (source_node_id, target_node_id, edge_type, access_path)
            if batch_key in seen_keys:
                continue
            seen_keys.add(batch_key)

            # Key includes access_path: the same identity can hold a role both
            # directly and via a group (live Okta). Looking up without it made
            # one_or_none() raise MultipleResultsFound and fail the sync.
            matches = existing_edges.get(batch_key, [])
            existing = matches[0] if matches else None
            for extra in matches[1:]:
                session.delete(extra)

            if existing is None:
                session.add(
                    GraphEdge(
                        id=uuid.uuid4(),
                        org_id=ctx.org_id,
                        source_node_id=source_node_id,
                        target_node_id=target_node_id,
                        edge_type=edge_type,
                        access_path=access_path,
                        source_connector_run_id=ctx.connector_run_id,
                        first_seen_at=now,
                        last_seen_at=now,
                        properties=rel.properties,
                    )
                )
            else:
                existing.last_seen_at = now
                existing.properties = rel.properties


def delete_stale_edges(session: Session, ctx: UpsertContext, run_started_at: datetime) -> int:
    """Remove edges this connector instance stopped observing.

    Edges carry `last_seen_at` and nothing ever read it. Nothing prunes them
    either, and no graph query filters on it, so revoked access stayed visible
    in Explore forever -- the one place an operator goes to ask "who can reach
    this". A grant removed six months ago still drew a line.

    Deletion rather than a tombstone, because the graph is a derived read-model
    and not a source of truth (ADR-0003). What actually happened is already
    recorded: the underlying relationship row emits a DELETED change, which is
    what `/changes` and the audit trail read. Re-granting simply writes the edge
    again.

    For the same reason this emits no Event of its own -- the relationship row's
    DELETED change already covers it, and a second row would double-count one
    revocation in the feed.

    Scoped through the run that wrote the edge, the way relationship rows are:
    edges have no application_instance_id of their own.

    **Must only be called on a complete, non-incremental run.** Absence is the
    signal here, and a run that could not read part of the tenant -- or that
    deliberately collected only audit logs -- has no evidence any of it is gone.
    `sync.pipeline` enforces that alongside the same guard on entity deletion
    detection.
    """
    # `upsert_edges` refreshes `last_seen_at` as pending ORM state. Flush it
    # before the bulk DELETE reads the column, or this run's own edges still
    # look stale and get pruned the moment they are re-observed.
    session.flush()

    owned_runs = select(ConnectorRun.id).where(ConnectorRun.connector_instance_id == ctx.connector_instance_id)
    result = session.execute(
        delete(GraphEdge).where(
            GraphEdge.org_id == ctx.org_id,
            GraphEdge.source_connector_run_id.in_(owned_runs),
            GraphEdge.last_seen_at < run_started_at,
        )
    )
    # `rowcount` is on the DBAPI cursor result; SQLAlchemy's generic `Result`
    # stub does not declare it, so it is read defensively rather than cast.
    return int(getattr(result, "rowcount", 0) or 0)


def delete_tombstoned_nodes(session: Session, ctx: UpsertContext, run_started_at: datetime) -> int:
    """Remove graph nodes whose entity row was tombstoned by this run.

    ``detect_deletions`` keeps the row (``deleted_at``) so evidence and the
    Changes feed still resolve, but the graph answers "who can reach what
    *now*", and a departed identity or a removed repository has no place in
    it. Incident edges go with the node; ``upsert_nodes`` recreates both if
    the provider ever reports the row again.

    Same precondition as ``delete_stale_edges``: complete, non-incremental runs
    only, because the tombstones themselves are only written on those.
    """
    session.flush()
    removed = 0
    for kind, model in _MODEL_BY_KIND.items():
        if kind in APPEND_ONLY_KINDS or kind not in _KIND_TO_NODE_TYPE:
            continue
        tombstoned_ids = select(model.id).where(
            model.application_instance_id == ctx.application_instance_id,
            model.deleted_at == run_started_at,
        )
        node_ids = select(GraphNode.id).where(
            GraphNode.org_id == ctx.org_id,
            GraphNode.node_type == _KIND_TO_NODE_TYPE[kind],
            GraphNode.object_id.in_(tombstoned_ids),
        )
        session.execute(
            delete(GraphEdge).where(
                GraphEdge.org_id == ctx.org_id,
                or_(GraphEdge.source_node_id.in_(node_ids), GraphEdge.target_node_id.in_(node_ids)),
            )
        )
        result = session.execute(delete(GraphNode).where(GraphNode.id.in_(node_ids)))
        removed += int(getattr(result, "rowcount", 0) or 0)
    return removed


def write_identity_link_edges(session: Session, *, org_id: uuid.UUID) -> int:
    """Draw one ``maps_to`` edge per correlated account pair, star-shaped.

    Explore's whole point is showing a person once rather than four times. The
    correlation itself lives in ``identity_links``; this projects it into the
    graph so the canvas can draw it and traversal can cross application
    boundaries. Star topology (representative → each member) rather than a
    clique, so a five-account person is four edges, not ten.

    Edges are rewritten wholesale for the org: correlation is a derived view,
    and a cluster that split must not leave a line behind. Runs after
    ``upsert_nodes``, so a node that no longer exists simply has no edge.
    """
    from kestrel.db.models.identity_link import IdentityLink

    session.flush()
    identity_nodes = {
        node.object_id: node.id
        for node in session.scalars(
            select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.node_type == GraphNodeType.IDENTITY)
        ).all()
    }
    session.execute(
        delete(GraphEdge).where(
            GraphEdge.org_id == org_id,
            GraphEdge.edge_type == GraphEdgeType.MAPS_TO,
            GraphEdge.access_path == AccessPath.FEDERATED,
        )
    )

    links = list(
        session.scalars(select(IdentityLink).where(IdentityLink.org_id == org_id, IdentityLink.member_count > 1)).all()
    )
    now = datetime.now(UTC)
    written = 0
    for link in links:
        if link.identity_id == link.representative_identity_id:
            continue
        source = identity_nodes.get(link.representative_identity_id)
        target = identity_nodes.get(link.identity_id)
        if source is None or target is None:
            continue
        session.add(
            GraphEdge(
                id=uuid.uuid4(),
                org_id=org_id,
                source_node_id=source,
                target_node_id=target,
                edge_type=GraphEdgeType.MAPS_TO,
                access_path=AccessPath.FEDERATED,
                properties={"match_kind": link.match_kind, "member_count": link.member_count},
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        written += 1
    session.flush()
    return written
