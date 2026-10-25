# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Bounded graph exploration: neighbor subgraphs + reachability with paths.

Answers "what can this identity reach?" and "who can reach this resource?"
with hop-level ``access_path`` so OAuth-derived edges stay visible.
Edge ``properties`` (permission_level) and OAuth scopes are attached at read
time for Explore readability.

when the focus is an identity, correlated accounts (email / unique
display-name) are treated as a single person — multi-start traversal with
sibling identity nodes collapsed onto the focused node.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kestrel.db.models.graph_edge import AccessPath, GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from kestrel.graph.context import detail_path_for_node, graph_focus_path_for_node
from kestrel.graph.edge_context import explain_edge, oauth_scopes_by_app
from kestrel.graph.queries import MAX_TRAVERSAL_DEPTH, TraversalDirection, search_nodes
from kestrel.identities.correlate import (
    collapse_identity_search_hits,
    identity_cluster_for,
)

DEFAULT_NEIGHBOR_MAX_NODES = 250
DEFAULT_PATHS_LIMIT = 75
MAX_PATHS_LIMIT = 200
# Traversal work is bounded by the requested output size, not just the output:
# at most ``max(_MIN_VISIT_CAP, size * _VISIT_CAP_FACTOR)`` nodes are visited
# (headroom for type / access-path filters applied after the walk), and each
# depth level fetches a bounded number of edges.
_VISIT_CAP_FACTOR = 4
_MIN_VISIT_CAP = 100
_EDGE_FETCH_FACTOR = 2
# Over-fetch search hits before identity collapse so ``limit`` is post-dedupe.
_SEARCH_OVERFETCH = 3

# Prefer the most operator-interesting access path when summarizing a hop chain.
_ACCESS_PATH_RANK: dict[str, int] = {
    AccessPath.OAUTH_DERIVED.value: 50,
    AccessPath.INHERITED_ROLE.value: 40,
    AccessPath.INHERITED_GROUP.value: 30,
    AccessPath.FEDERATED.value: 20,
    AccessPath.DIRECT.value: 10,
}


def _node_type_str(node_type: GraphNodeType | str) -> str:
    return node_type.value if isinstance(node_type, GraphNodeType) else str(node_type)


def serialize_node(
    node: GraphNode,
    *,
    is_start: bool = False,
    extra_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    props = dict(node.properties or {})
    if extra_properties:
        props.update(extra_properties)
    payload: dict[str, Any] = {
        "id": node.id,
        "node_type": _node_type_str(node.node_type),
        "object_id": node.object_id,
        "label": node.label,
        "properties": props,
    }
    if is_start:
        payload["is_start"] = True
    return payload


def serialize_search_item(
    node: GraphNode,
    *,
    application_types: list[str] | None = None,
    account_count: int | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": node.id,
        "node_type": _node_type_str(node.node_type),
        "object_id": node.object_id,
        "label": node.label,
        "detail_path": detail_path_for_node(node),
        "graph_focus_path": graph_focus_path_for_node(node),
    }
    if application_types is not None:
        item["application_types"] = application_types
    if account_count is not None:
        item["account_count"] = account_count
    return item


def resolve_node(
    db: Session,
    *,
    org_id: uuid.UUID,
    node_type: GraphNodeType | str,
    object_id: uuid.UUID,
) -> GraphNode | None:
    parsed = GraphNodeType(node_type) if isinstance(node_type, str) else node_type
    return db.scalars(
        select(GraphNode).where(
            GraphNode.org_id == org_id,
            GraphNode.node_type == parsed,
            GraphNode.object_id == object_id,
        )
    ).first()


def get_org_node(db: Session, *, org_id: uuid.UUID, node_id: uuid.UUID) -> GraphNode | None:
    node = db.get(GraphNode, node_id)
    if node is None or node.org_id != org_id:
        return None
    return node


def _cluster_graph_nodes(
    db: Session, *, org_id: uuid.UUID, start: GraphNode
) -> tuple[list[GraphNode], dict[str, Any] | None]:
    """Resolve correlated identity graph nodes for a focus identity.

    Returns (seed_nodes including start, cluster_meta or None).
    Non-identity starts return ([start], None).
    """
    if start.node_type != GraphNodeType.IDENTITY:
        return [start], None

    cluster = identity_cluster_for(db, org_id=org_id, identity_id=start.object_id)
    if cluster is None or cluster["member_count"] <= 1:
        return [start], cluster

    identity_ids = [uuid.UUID(i) for i in cluster["identity_ids"]]
    nodes = list(
        db.scalars(
            select(GraphNode).where(
                GraphNode.org_id == org_id,
                GraphNode.node_type == GraphNodeType.IDENTITY,
                GraphNode.object_id.in_(identity_ids),
            )
        ).all()
    )
    if not nodes:
        return [start], cluster
    # Ensure focus start is present and first.
    by_id = {n.id: n for n in nodes}
    by_id[start.id] = start
    ordered = [start] + [n for n in nodes if n.id != start.id]
    return ordered, cluster


def _cluster_start_props(cluster: dict[str, Any] | None) -> dict[str, Any]:
    if not cluster:
        return {}
    return {
        "cluster_size": cluster["member_count"],
        "application_types": cluster["application_types"],
    }


def _collect_oauth_app_ids_for_edges(edges: list[GraphEdge], nodes_by_id: dict[uuid.UUID, GraphNode]) -> list[uuid.UUID]:
    """OAuth app entity PKs targeted by possesses_scope edges."""
    app_ids: set[uuid.UUID] = set()
    for edge in edges:
        if edge.edge_type != GraphEdgeType.POSSESSES_SCOPE:
            continue
        # Prefer target (identity → oauth_app outbound); fall back to source for inbound.
        for endpoint_id in (edge.target_node_id, edge.source_node_id):
            node = nodes_by_id.get(endpoint_id)
            if node is not None and node.node_type == GraphNodeType.OAUTH_APPLICATION:
                app_ids.add(node.object_id)
                break
    return list(app_ids)


def serialize_edge(
    edge: GraphEdge,
    *,
    scopes_by_app: dict[uuid.UUID, list[dict[str, Any]]] | None = None,
    nodes_by_id: dict[uuid.UUID, GraphNode] | None = None,
    source_node_id: uuid.UUID | None = None,
    target_node_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Serialize a graph edge including properties and optional OAuth scopes."""
    props: dict[str, Any] = dict(edge.properties or {})
    src = source_node_id if source_node_id is not None else edge.source_node_id
    tgt = target_node_id if target_node_id is not None else edge.target_node_id
    if scopes_by_app and nodes_by_id and edge.edge_type == GraphEdgeType.POSSESSES_SCOPE:
        for endpoint_id in (tgt, src):
            node = nodes_by_id.get(endpoint_id)
            if node is not None and node.node_type == GraphNodeType.OAUTH_APPLICATION:
                scopes = scopes_by_app.get(node.object_id)
                if scopes:
                    props["scopes"] = scopes
                break
    return {
        "id": edge.id,
        "source_node_id": src,
        "target_node_id": tgt,
        "edge_type": edge.edge_type.value,
        "access_path": edge.access_path.value if edge.access_path else None,
        "properties": props,
    }


def _primary_access_path(access_paths: list[str | None]) -> str | None:
    best: str | None = None
    best_rank = -1
    for raw in access_paths:
        if not raw:
            continue
        rank = _ACCESS_PATH_RANK.get(raw, 0)
        if rank > best_rank:
            best = raw
            best_rank = rank
    return best


@dataclass
class _Traversal:
    """BFS result. ``parent`` maps each reached non-seed node to the node it was
    first reached from and the edge used; insertion order is BFS order, so the
    first entry for a node is a shortest path. ``capped`` means the visit cap
    stopped the walk, so more nodes may be reachable than were returned."""

    parent: dict[uuid.UUID, tuple[uuid.UUID, GraphEdge]] = field(default_factory=dict)
    capped: bool = False


def _visit_cap(output_size: int) -> int:
    return max(_MIN_VISIT_CAP, output_size * _VISIT_CAP_FACTOR)


def _bounded_bfs(
    db: Session,
    *,
    org_id: uuid.UUID,
    seed_ids: set[uuid.UUID],
    depth: int,
    direction: TraversalDirection,
    visit_cap: int,
) -> _Traversal:
    """Multi-seed BFS, one edge query per depth level, at most ``visit_cap`` nodes.

    Seeds sit at depth 0 and do not consume hop budget. Each level fetches the
    edges incident to the whole frontier in one ``IN`` query, limited in rows,
    so a hub node with tens of thousands of edges costs one bounded query
    rather than a walk of everything behind it.
    """
    result = _Traversal()
    visited: set[uuid.UUID] = set(seed_ids)
    frontier: set[uuid.UUID] = set(seed_ids)
    follow_out = direction in ("out", "both")
    follow_in = direction in ("in", "both")

    for _level in range(depth):
        if not frontier or result.capped:
            break
        conditions = []
        if follow_out:
            conditions.append(GraphEdge.source_node_id.in_(frontier))
        if follow_in:
            conditions.append(GraphEdge.target_node_id.in_(frontier))
        # Edges back into visited nodes also come back, so leave room for one
        # per frontier node on top of the remaining visit budget.
        fetch_limit = (visit_cap - len(result.parent) + len(frontier)) * _EDGE_FETCH_FACTOR
        edges = db.scalars(select(GraphEdge).where(GraphEdge.org_id == org_id, or_(*conditions)).limit(fetch_limit)).all()
        if len(edges) >= fetch_limit:
            result.capped = True

        next_frontier: set[uuid.UUID] = set()
        for edge in edges:
            if result.capped and len(result.parent) >= visit_cap:
                break
            steps: list[tuple[uuid.UUID, uuid.UUID]] = []
            if follow_out and edge.source_node_id in frontier:
                steps.append((edge.source_node_id, edge.target_node_id))
            if follow_in and edge.target_node_id in frontier:
                steps.append((edge.target_node_id, edge.source_node_id))
            for current_id, nxt in steps:
                if nxt in visited:
                    continue
                if len(result.parent) >= visit_cap:
                    result.capped = True
                    break
                visited.add(nxt)
                result.parent[nxt] = (current_id, edge)
                next_frontier.add(nxt)
        frontier = next_frontier
    return result


def _rewrite_endpoint(node_id: uuid.UUID, *, focus_id: uuid.UUID, seed_ids: set[uuid.UUID]) -> uuid.UUID:
    return focus_id if node_id in seed_ids else node_id


def neighbor_subgraph(
    db: Session,
    *,
    org_id: uuid.UUID,
    start: GraphNode,
    depth: int = 3,
    direction: TraversalDirection = "out",
    node_types: list[GraphNodeType] | None = None,
    access_paths: list[AccessPath] | None = None,
    max_nodes: int = DEFAULT_NEIGHBOR_MAX_NODES,
) -> dict[str, Any]:
    """Bounded neighbor expansion matching the historical neighbors API shape.

    Identity focus: expand from every correlated account, then collapse sibling
    identity nodes onto the focused start node.
    """
    capped_depth = max(1, min(depth, MAX_TRAVERSAL_DEPTH))
    capped_max = max(10, min(max_nodes, DEFAULT_NEIGHBOR_MAX_NODES))

    seed_nodes, cluster = _cluster_graph_nodes(db, org_id=org_id, start=start)
    seed_ids = {n.id for n in seed_nodes}
    start_props = _cluster_start_props(cluster)
    sibling_ids = seed_ids - {start.id}

    traversal = _bounded_bfs(
        db,
        org_id=org_id,
        seed_ids=seed_ids,
        depth=capped_depth,
        direction=direction,
        visit_cap=_visit_cap(capped_max),
    )
    # BFS order, nearest first, so truncation below keeps the closest nodes.
    reachable_order = list(traversal.parent)
    reachable_ids = set(reachable_order) | seed_ids

    type_filter = {t.value if isinstance(t, GraphNodeType) else str(t) for t in (node_types or [])}
    path_filter = {(p.value if isinstance(p, AccessPath) else str(p)) for p in (access_paths or [])}

    # Load reachable + seed nodes for type filtering and serialization.
    load_ids = reachable_ids | seed_ids
    nodes_by_id: dict[uuid.UUID, GraphNode] = {start.id: start}
    if load_ids:
        for loaded in db.scalars(select(GraphNode).where(GraphNode.id.in_(list(load_ids)))).all():
            nodes_by_id[loaded.id] = loaded

    filtered: list[uuid.UUID] = []
    for nid in reachable_order:
        if nid == start.id or nid in sibling_ids:
            continue
        candidate = nodes_by_id.get(nid)
        if candidate is None:
            continue
        if type_filter and candidate.node_type.value not in type_filter:
            continue
        filtered.append(nid)

    truncated = traversal.capped or len(filtered) > capped_max - 1
    capped_ids = set(filtered[: max(capped_max - 1, 0)])
    edge_query_ids = capped_ids | seed_ids | {start.id}

    edge_rows: list[GraphEdge] = []
    if edge_query_ids:
        edge_rows = list(
            db.scalars(
                select(GraphEdge).where(
                    GraphEdge.org_id == org_id,
                    GraphEdge.source_node_id.in_(list(edge_query_ids)),
                    GraphEdge.target_node_id.in_(list(edge_query_ids)),
                )
            ).all()
        )

    if path_filter:
        edge_rows = [e for e in edge_rows if e.access_path is not None and e.access_path.value in path_filter]
        # When filtering by access path, keep endpoints of matching edges.
        capped_ids = set()
        for e in edge_rows:
            for endpoint in (e.source_node_id, e.target_node_id):
                rewritten = _rewrite_endpoint(endpoint, focus_id=start.id, seed_ids=seed_ids)
                if rewritten != start.id:
                    capped_ids.add(rewritten)

    rewritten_edges: list[tuple[GraphEdge, uuid.UUID, uuid.UUID]] = []
    seen_edge_keys: set[tuple[uuid.UUID, uuid.UUID, str, str | None]] = set()
    visible_ids: set[uuid.UUID] = {start.id}
    for edge in edge_rows:
        src = _rewrite_endpoint(edge.source_node_id, focus_id=start.id, seed_ids=seed_ids)
        tgt = _rewrite_endpoint(edge.target_node_id, focus_id=start.id, seed_ids=seed_ids)
        if src == tgt:
            continue
        access = edge.access_path.value if edge.access_path else None
        key = (src, tgt, edge.edge_type.value, access)
        if key in seen_edge_keys:
            continue
        seen_edge_keys.add(key)
        if src != start.id and src not in capped_ids:
            continue
        if tgt != start.id and tgt not in capped_ids:
            continue
        rewritten_edges.append((edge, src, tgt))
        visible_ids.add(src)
        visible_ids.add(tgt)

    if len(visible_ids) > capped_max:
        truncated = True
        keep = {start.id}
        for nid in filtered:
            if nid in visible_ids:
                keep.add(nid)
            if len(keep) >= capped_max:
                break
        visible_ids = keep
        rewritten_edges = [(e, s, t) for e, s, t in rewritten_edges if s in visible_ids and t in visible_ids]

    for nid in list(visible_ids):
        if nid not in nodes_by_id:
            missing_node = db.get(GraphNode, nid)
            if missing_node is not None:
                nodes_by_id[nid] = missing_node

    nodes_payload = [serialize_node(start, is_start=True, extra_properties=start_props)]
    for nid in visible_ids:
        if nid == start.id:
            continue
        resolved = nodes_by_id.get(nid)
        if resolved is None:
            continue
        nodes_payload.append(serialize_node(resolved))

    scopes_by_app = oauth_scopes_by_app(
        db,
        org_id=org_id,
        oauth_app_ids=_collect_oauth_app_ids_for_edges([e for e, _, _ in rewritten_edges], nodes_by_id),
    )
    edges_payload = [
        serialize_edge(
            e,
            scopes_by_app=scopes_by_app,
            nodes_by_id=nodes_by_id,
            source_node_id=src,
            target_node_id=tgt,
        )
        for e, src, tgt in rewritten_edges
    ]

    return {
        "depth": capped_depth,
        "direction": direction,
        "start_node_id": start.id,
        "truncated": truncated,
        "node_count": len(nodes_payload),
        "edge_count": len(edges_payload),
        "nodes": nodes_payload,
        "edges": edges_payload,
        "accounts": cluster["accounts"] if cluster else None,
    }


def reachability_paths(
    db: Session,
    *,
    org_id: uuid.UUID,
    start: GraphNode,
    depth: int = 3,
    direction: Literal["out", "in"] = "out",
    limit: int = DEFAULT_PATHS_LIMIT,
    destination_types: list[GraphNodeType] | None = None,
) -> dict[str, Any]:
    """Shortest path from ``start`` to each reachable node, with hop explainability.

    ``direction=out`` answers what the start can reach; ``in`` answers who can
    reach the start. Bidirectional is excluded here so each path has a clear
    narrative direction for the Explore UI.

    Identity clusters: all correlated accounts are depth-0 seeds; sibling
    identity nodes are rewritten to the focus start.
    """
    if direction not in ("out", "in"):
        raise ValueError("direction must be 'out' or 'in'")

    capped_depth = max(1, min(depth, MAX_TRAVERSAL_DEPTH))
    capped_limit = max(1, min(limit, MAX_PATHS_LIMIT))
    type_filter = {(t if isinstance(t, GraphNodeType) else GraphNodeType(t)) for t in (destination_types or [])}

    seed_nodes, cluster = _cluster_graph_nodes(db, org_id=org_id, start=start)
    seed_ids = {n.id for n in seed_nodes}
    start_props = _cluster_start_props(cluster)

    # BFS: first time we see a node is the shortest path. Seeds start at depth 0.
    traversal = _bounded_bfs(
        db,
        org_id=org_id,
        seed_ids=seed_ids,
        depth=capped_depth,
        direction=direction,
        visit_cap=_visit_cap(capped_limit),
    )
    parent = traversal.parent
    nodes_cache: dict[uuid.UUID, GraphNode] = {n.id: n for n in seed_nodes}
    nodes_cache[start.id] = start

    destination_ids = list(parent)
    missing = [nid for nid in destination_ids if nid not in nodes_cache]
    if missing:
        for node in db.scalars(select(GraphNode).where(GraphNode.id.in_(missing))).all():
            nodes_cache[node.id] = node

    path_edges: list[GraphEdge] = []
    for dest_id in destination_ids:
        cursor = dest_id
        while cursor not in seed_ids:
            prev_id, edge = parent[cursor]
            path_edges.append(edge)
            cursor = prev_id
    scopes_by_app = oauth_scopes_by_app(
        db,
        org_id=org_id,
        oauth_app_ids=_collect_oauth_app_ids_for_edges(path_edges, nodes_cache),
    )

    paths: list[dict[str, Any]] = []
    for dest_id in destination_ids:
        dest = nodes_cache.get(dest_id)
        if dest is None:
            continue
        if type_filter and dest.node_type not in type_filter:
            continue

        # Reconstruct hops focus → … → dest (rewrite seed hops onto start).
        chain: list[tuple[uuid.UUID, GraphEdge, uuid.UUID]] = []
        cursor = dest_id
        while cursor not in seed_ids:
            prev_id, edge = parent[cursor]
            chain.append((prev_id, edge, cursor))
            cursor = prev_id
        chain.reverse()

        hops: list[dict[str, Any]] = []
        access_values: list[str | None] = []
        for src_id, edge, tgt_id in chain:
            display_src_id = _rewrite_endpoint(src_id, focus_id=start.id, seed_ids=seed_ids)
            display_tgt_id = _rewrite_endpoint(tgt_id, focus_id=start.id, seed_ids=seed_ids)
            src = nodes_cache[display_src_id] if display_src_id == start.id else nodes_cache[src_id]
            if display_src_id == start.id:
                src = start
            tgt = nodes_cache[tgt_id]
            access = edge.access_path.value if edge.access_path else None
            access_values.append(access)
            edge_payload = serialize_edge(
                edge,
                scopes_by_app=scopes_by_app,
                nodes_by_id=nodes_cache,
                source_node_id=display_src_id,
                target_node_id=display_tgt_id,
            )
            hops.append(
                {
                    "from": serialize_node(
                        src,
                        is_start=display_src_id == start.id,
                        extra_properties=start_props if display_src_id == start.id else None,
                    ),
                    "to": serialize_node(tgt),
                    "edge_id": edge.id,
                    "edge_type": edge.edge_type.value,
                    "access_path": access,
                    "properties": edge_payload["properties"],
                    "explanation": explain_edge(edge, src, tgt),
                }
            )

        paths.append(
            {
                "destination": serialize_node(dest),
                "hop_count": len(hops),
                "access_paths": [a for a in dict.fromkeys(access_values) if a],
                "primary_access_path": _primary_access_path(access_values),
                "hops": hops,
            }
        )

    # Prefer interesting destinations: oauth / roles / resources, then hop length.
    def _sort_key(path: dict[str, Any]) -> tuple:
        dest = path["destination"]
        type_rank = {
            "oauth_application": 0,
            "role": 1,
            "resource": 2,
            "permission": 3,
            "group": 4,
            "identity": 5,
            "application": 6,
            "setting": 7,
        }.get(dest["node_type"], 9)
        path_rank = -_ACCESS_PATH_RANK.get(path.get("primary_access_path") or "", 0)
        return (type_rank, path_rank, path["hop_count"], dest["label"].lower())

    paths.sort(key=_sort_key)
    # When the visit cap stopped the walk, ``total`` is a lower bound.
    truncated = traversal.capped or len(paths) > capped_limit
    capped_paths = paths[:capped_limit]

    by_type: dict[str, int] = {}
    by_access: dict[str, int] = {}
    for path in capped_paths:
        nt = path["destination"]["node_type"]
        by_type[nt] = by_type.get(nt, 0) + 1
        primary = path.get("primary_access_path") or "unspecified"
        by_access[primary] = by_access.get(primary, 0) + 1

    return {
        "start": serialize_node(start, is_start=True, extra_properties=start_props),
        "direction": direction,
        "depth": capped_depth,
        "total": len(paths),
        "returned": len(capped_paths),
        "truncated": truncated,
        "paths": capped_paths,
        "summary": {
            "by_node_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_access_path": dict(sorted(by_access.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        "accounts": cluster["accounts"] if cluster else None,
    }


def search_graph_nodes(
    db: Session,
    *,
    org_id: uuid.UUID,
    q: str,
    node_types: list[GraphNodeType] | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Label search with identity cluster collapse."""
    from kestrel.graph.queries import MAX_SEARCH_LIMIT

    capped = max(1, min(limit, MAX_SEARCH_LIMIT))
    overfetch = min(MAX_SEARCH_LIMIT, capped * _SEARCH_OVERFETCH)
    raw_nodes = search_nodes(db, org_id=org_id, q=q, node_types=node_types, limit=overfetch)

    identity_ids = [n.object_id for n in raw_nodes if n.node_type == GraphNodeType.IDENTITY]
    cluster_meta = collapse_identity_search_hits(db, org_id=org_id, identity_object_ids=identity_ids) if identity_ids else {}

    items: list[dict[str, Any]] = []
    seen_reps: set[uuid.UUID] = set()
    for node in raw_nodes:
        if len(items) >= capped:
            break
        if node.node_type != GraphNodeType.IDENTITY:
            items.append(serialize_search_item(node))
            continue
        meta = cluster_meta.get(node.object_id)
        if meta is None:
            items.append(serialize_search_item(node, application_types=[], account_count=1))
            continue
        rep_id = meta["representative_identity_id"]
        if rep_id in seen_reps:
            continue
        # Prefer emitting the representative's graph node when present in hits;
        # otherwise emit the first matching member we saw.
        emit = node
        if node.object_id != rep_id:
            for candidate in raw_nodes:
                if candidate.node_type == GraphNodeType.IDENTITY and candidate.object_id == rep_id:
                    emit = candidate
                    break
            else:
                # Resolve representative node so focus URL uses the IdP account.
                rep_node = resolve_node(db, org_id=org_id, node_type=GraphNodeType.IDENTITY, object_id=rep_id)
                if rep_node is not None:
                    emit = rep_node
        seen_reps.add(rep_id)
        # Prefer cluster display name when the hit label is a login/handle.
        label = emit.label
        if meta.get("display_name"):
            label = meta["display_name"]
        item = serialize_search_item(
            emit,
            application_types=list(meta["application_types"]),
            account_count=int(meta["member_count"]),
        )
        item["label"] = label
        items.append(item)

    return {"items": items}
