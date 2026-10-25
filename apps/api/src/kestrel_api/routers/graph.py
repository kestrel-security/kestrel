# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identity graph API.

Bounded Explore surface over recursive CTE traversal: resolve, search,
neighbors, and reachability paths with access_path hop semantics.
"""

from __future__ import annotations

import uuid

import kestrel.graph.explore as graph_explore
from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.db.models.graph_edge import AccessPath, GraphNodeType
from kestrel.db.models.org import Organization
from kestrel.graph.context import graph_node_context
from kestrel.graph.edge_context import graph_edge_context
from kestrel.graph.queries import MAX_TRAVERSAL_DEPTH, TraversalDirection
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db

router = APIRouter(prefix="/graph", tags=["graph"])


def _parse_node_types(raw: str | None) -> list[GraphNodeType] | None:
    if not raw or not raw.strip():
        return None
    out: list[GraphNodeType] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            out.append(GraphNodeType(token))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown node_type '{token}'",
            ) from exc
    return out or None


def _parse_access_paths(raw: str | None) -> list[AccessPath] | None:
    if not raw or not raw.strip():
        return None
    out: list[AccessPath] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            out.append(AccessPath(token))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown access_path '{token}'",
            ) from exc
    return out or None


@router.get("/resolve")
def resolve_graph_node(
    node_type: str = Query(...),
    object_id: uuid.UUID = Query(...),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Map an entity PK to its graph_nodes.id (different concepts — ADR-0003)."""
    try:
        parsed = GraphNodeType(node_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Unknown node_type '{node_type}'") from exc

    node = graph_explore.resolve_node(db, org_id=org.id, node_type=parsed, object_id=object_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Graph node not found")
    return graph_explore.serialize_node(node)


@router.get("/search")
def search_graph(
    q: str = Query(..., min_length=1),
    node_types: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=50),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Label search for the Explore picker."""
    return graph_explore.search_graph_nodes(
        db,
        org_id=org.id,
        q=q.strip(),
        node_types=_parse_node_types(node_types),
        limit=limit,
    )


@router.get("/nodes/{node_id}/neighbors")
def graph_neighbors(
    node_id: uuid.UUID,
    depth: int = Query(default=3, ge=1, le=MAX_TRAVERSAL_DEPTH),
    direction: TraversalDirection = Query(default="out"),
    node_types: str | None = Query(default=None),
    access_paths: str | None = Query(default=None),
    max_nodes: int = Query(default=250, ge=10, le=250),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Bounded-depth neighbor expansion (nodes + edges)."""
    start = graph_explore.get_org_node(db, org_id=org.id, node_id=node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Graph node not found")
    return graph_explore.neighbor_subgraph(
        db,
        org_id=org.id,
        start=start,
        depth=depth,
        direction=direction,
        node_types=_parse_node_types(node_types),
        access_paths=_parse_access_paths(access_paths),
        max_nodes=max_nodes,
    )


@router.get("/nodes/{node_id}/paths")
def graph_paths(
    node_id: uuid.UUID,
    depth: int = Query(default=3, ge=1, le=MAX_TRAVERSAL_DEPTH),
    direction: str = Query(default="out", pattern="^(out|in)$"),
    destination_types: str | None = Query(default=None),
    limit: int = Query(default=75, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Shortest paths from (out) or to (in) this node, with hop access_path."""
    start = graph_explore.get_org_node(db, org_id=org.id, node_id=node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Graph node not found")
    assert direction in ("out", "in")
    return graph_explore.reachability_paths(
        db,
        org_id=org.id,
        start=start,
        depth=depth,
        direction=direction,  # type: ignore[arg-type]
        limit=limit,
        destination_types=_parse_node_types(destination_types),
    )


@router.get("/nodes/{node_id}/context")
def graph_context(
    node_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    start = graph_explore.get_org_node(db, org_id=org.id, node_id=node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Graph node not found")
    return graph_node_context(db, start)


@router.get("/edges/{edge_id}")
def graph_edge(
    edge_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    from kestrel.db.models.graph_edge import GraphEdge, GraphNode

    edge = db.get(GraphEdge, edge_id)
    if edge is None or edge.org_id != org.id:
        raise HTTPException(status_code=404, detail="Graph edge not found")
    source_node = db.get(GraphNode, edge.source_node_id)
    target_node = db.get(GraphNode, edge.target_node_id)
    if source_node is None or target_node is None:
        raise HTTPException(status_code=404, detail="Graph edge endpoints missing")
    if source_node.org_id != org.id or target_node.org_id != org.id:
        raise HTTPException(status_code=404, detail="Graph edge not found")
    return graph_edge_context(db, edge, source_node, target_node)
