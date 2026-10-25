# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Blast radius: open findings on graph neighbors of a finding's subject.

Also builds the bounded neighbor subgraph and the incident-handoff export
package (blast radius + subgraph + attack path) with its CSV flattening.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.graph_edge import GraphEdge, GraphNode, GraphNodeType
from kestrel.findings.attack_path import attack_path as build_attack_path
from kestrel.findings.investigation._common import _findings_list_path, _identity_explore_path
from kestrel.graph.queries import neighbors, reachable_nodes

BLAST_RADIUS_DEPTH_DEFAULT = 2
BLAST_RADIUS_DEPTH_MAX = 4
BLAST_RADIUS_NEIGHBORS_LIMIT = 24
BLAST_RADIUS_FINDINGS_LIMIT = 20
BLAST_RADIUS_PER_NEIGHBOR_FINDINGS = 3
# Higher caps for incident-handoff export; UI detail stays compact.
BLAST_RADIUS_EXPORT_NEIGHBORS_LIMIT = 200
BLAST_RADIUS_EXPORT_FINDINGS_LIMIT = 500
BLAST_RADIUS_EXPORT_PER_NEIGHBOR_FINDINGS = 50
BLAST_RADIUS_EXPORT_SUBGRAPH_NODES_LIMIT = 500

# Graph node types that can also be finding subjects.
_SUBJECT_NODE_TYPES = frozenset(
    {
        GraphNodeType.IDENTITY,
        GraphNodeType.RESOURCE,
        GraphNodeType.OAUTH_APPLICATION,
        GraphNodeType.SETTING,
    }
)


def _node_type_str(node_type: GraphNodeType | str) -> str:
    return node_type.value if isinstance(node_type, GraphNodeType) else str(node_type)


def _subject_graph_node(db: Session, finding: Finding) -> GraphNode | None:
    try:
        node_type = GraphNodeType(finding.subject_type.value)
    except ValueError:
        return None
    return db.scalars(
        select(GraphNode).where(
            GraphNode.org_id == finding.org_id,
            GraphNode.node_type == node_type,
            GraphNode.object_id == finding.subject_id,
        )
    ).one_or_none()


def _neighbor_paths_from_ref(*, node_type: str, object_id: uuid.UUID) -> dict[str, str | None]:
    is_identity = node_type == GraphNodeType.IDENTITY.value
    detail_path = f"/identities/{object_id}" if is_identity else None
    graph_focus = _identity_explore_path(object_id) if is_identity else None
    findings_path = (
        _findings_list_path(node_type, object_id) if node_type in {t.value for t in _SUBJECT_NODE_TYPES} else None
    )
    return {
        "detail_path": detail_path,
        "graph_focus_path": graph_focus,
        "findings_list_path": findings_path,
    }


def blast_radius(
    db: Session,
    finding: Finding,
    *,
    depth: int = BLAST_RADIUS_DEPTH_DEFAULT,
    neighbors_limit: int = BLAST_RADIUS_NEIGHBORS_LIMIT,
    findings_limit: int = BLAST_RADIUS_FINDINGS_LIMIT,
    per_neighbor_findings: int = BLAST_RADIUS_PER_NEIGHBOR_FINDINGS,
) -> dict[str, Any]:
    """Open findings on graph neighbors of the subject.

    Goes beyond same-subject `related_findings`: walk the access graph from
    the subject's node and surface open findings on reachable identity /
    resource / OAuth nodes. Groups and roles expand reachability but are not
    finding subjects themselves.
    """
    capped_depth = max(1, min(depth, BLAST_RADIUS_DEPTH_MAX))
    empty: dict[str, Any] = {
        "depth": capped_depth,
        "subject_node_id": None,
        "neighbor_count": 0,
        "open_finding_count": 0,
        "neighbors": [],
        "findings": [],
    }
    start = _subject_graph_node(db, finding)
    if start is None:
        return empty

    subject_type_values = {t.value for t in _SUBJECT_NODE_TYPES}
    reachable = reachable_nodes(db, org_id=finding.org_id, start_node_id=start.id, max_depth=capped_depth)
    ordered_neighbors: list[tuple[uuid.UUID, str, uuid.UUID, str, str | None]] = []
    seen_objects: set[tuple[str, uuid.UUID]] = set()
    for ref in reachable:
        node_type = _node_type_str(ref.node_type)
        if node_type not in subject_type_values:
            continue
        if ref.id == start.id:
            continue
        key = (node_type, ref.object_id)
        if key in seen_objects:
            continue
        seen_objects.add(key)
        props = ref.properties or {}
        app_type = props.get("application_type") if isinstance(props, dict) else None
        app_type_str = app_type if isinstance(app_type, str) else None
        ordered_neighbors.append((ref.id, node_type, ref.object_id, ref.label, app_type_str))
        if len(ordered_neighbors) >= neighbors_limit:
            break

    if not ordered_neighbors:
        return {**empty, "subject_node_id": start.id}

    ids_by_type: dict[FindingSubjectType, set[uuid.UUID]] = {
        FindingSubjectType.IDENTITY: set(),
        FindingSubjectType.RESOURCE: set(),
        FindingSubjectType.OAUTH_APPLICATION: set(),
        FindingSubjectType.SETTING: set(),
    }
    for _nid, node_type, object_id, _label, _app in ordered_neighbors:
        ids_by_type[FindingSubjectType(node_type)].add(object_id)

    open_rows: list[Finding] = []
    for subject_type, ids in ids_by_type.items():
        if not ids:
            continue
        open_rows.extend(
            db.scalars(
                select(Finding)
                .where(
                    Finding.org_id == finding.org_id,
                    Finding.subject_type == subject_type,
                    Finding.subject_id.in_(ids),
                    Finding.status == FindingStatus.OPEN,
                    Finding.id != finding.id,
                )
                .order_by(Finding.last_seen_at.desc(), Finding.id.desc())
            ).all()
        )

    open_rows = [f for f in open_rows if not (f.subject_type == finding.subject_type and f.subject_id == finding.subject_id)]
    open_rows.sort(key=lambda f: (f.last_seen_at, f.id), reverse=True)

    by_subject: dict[tuple[str, uuid.UUID], list[Finding]] = {}
    for f in open_rows:
        by_subject.setdefault((f.subject_type.value, f.subject_id), []).append(f)

    label_by_key = {(node_type, object_id): label for _nid, node_type, object_id, label, _app in ordered_neighbors}

    neighbors_out: list[dict[str, Any]] = []
    for node_id, node_type, object_id, label, application_type in ordered_neighbors:
        subject_findings = by_subject.get((node_type, object_id), [])
        if not subject_findings:
            continue
        paths = _neighbor_paths_from_ref(node_type=node_type, object_id=object_id)
        neighbors_out.append(
            {
                "node_id": node_id,
                "node_type": node_type,
                "object_id": object_id,
                "label": label,
                "application_type": application_type,
                **paths,
                "open_finding_count": len(subject_findings),
                "open_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "last_seen_at": f.last_seen_at.isoformat(),
                    }
                    for f in subject_findings[:per_neighbor_findings]
                ],
            }
        )

    flat = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "subject_type": f.subject_type.value,
            "subject_id": f.subject_id,
            "subject_label": label_by_key.get((f.subject_type.value, f.subject_id)),
            "last_seen_at": f.last_seen_at.isoformat(),
        }
        for f in open_rows[:findings_limit]
    ]

    return {
        "depth": capped_depth,
        "subject_node_id": start.id,
        "neighbor_count": len(ordered_neighbors),
        "open_finding_count": len(open_rows),
        "neighbors": neighbors_out,
        "findings": flat,
    }


def blast_radius_subgraph(
    db: Session,
    finding: Finding,
    *,
    depth: int = BLAST_RADIUS_DEPTH_DEFAULT,
    nodes_limit: int = BLAST_RADIUS_EXPORT_SUBGRAPH_NODES_LIMIT,
) -> dict[str, Any]:
    """Bounded neighbor subgraph (nodes + edges) around the finding subject.

    Mirrors `GET /graph/nodes/{id}/neighbors` shape for incident handoff
    without requiring a separate graph-node resolve step.
    """
    capped_depth = max(1, min(depth, BLAST_RADIUS_DEPTH_MAX))
    empty: dict[str, Any] = {
        "depth": capped_depth,
        "subject_node_id": None,
        "truncated": False,
        "nodes": [],
        "edges": [],
    }
    start = _subject_graph_node(db, finding)
    if start is None:
        return empty

    reachable = neighbors(db, org_id=finding.org_id, node_id=start.id, depth=capped_depth)
    truncated = len(reachable) > nodes_limit - 1
    capped_reachable = reachable[: max(nodes_limit - 1, 0)]
    node_ids = {n.id for n in capped_reachable} | {start.id}

    edges = db.scalars(
        select(GraphEdge).where(
            GraphEdge.org_id == finding.org_id,
            GraphEdge.source_node_id.in_(node_ids),
            GraphEdge.target_node_id.in_(node_ids),
        )
    ).all()

    nodes_payload: list[dict[str, Any]] = [
        {
            "id": start.id,
            "node_type": start.node_type.value,
            "object_id": start.object_id,
            "label": start.label,
            "is_subject": True,
        }
    ]
    for ref in capped_reachable:
        nodes_payload.append(
            {
                "id": ref.id,
                "node_type": _node_type_str(ref.node_type),
                "object_id": ref.object_id,
                "label": ref.label,
                "is_subject": False,
            }
        )

    edges_payload = [
        {
            "id": e.id,
            "source_node_id": e.source_node_id,
            "target_node_id": e.target_node_id,
            "edge_type": e.edge_type.value,
            "access_path": e.access_path.value if e.access_path else None,
        }
        for e in edges
    ]
    return {
        "depth": capped_depth,
        "subject_node_id": start.id,
        "truncated": truncated,
        "nodes": nodes_payload,
        "edges": edges_payload,
    }


def export_blast_radius(
    db: Session,
    finding: Finding,
    *,
    depth: int = BLAST_RADIUS_DEPTH_DEFAULT,
) -> dict[str, Any]:
    """Incident-handoff package: blast-radius findings + graph subgraph.

    Uses higher finding/neighbor caps than the workbench detail panel so
    ticket/SIEM attachments are more complete within bounded limits.
    Includes ``attack_path`` when available — never fabricated.
    """
    from kestrel.findings.attack_path import ATTACK_PATH_DEPTH_MAX

    radius = blast_radius(
        db,
        finding,
        depth=depth,
        neighbors_limit=BLAST_RADIUS_EXPORT_NEIGHBORS_LIMIT,
        findings_limit=BLAST_RADIUS_EXPORT_FINDINGS_LIMIT,
        per_neighbor_findings=BLAST_RADIUS_EXPORT_PER_NEIGHBOR_FINDINGS,
    )
    subgraph = blast_radius_subgraph(db, finding, depth=radius["depth"])
    path = build_attack_path(db, finding, max_depth=min(radius["depth"] + 2, ATTACK_PATH_DEPTH_MAX))
    return {
        "finding_id": finding.id,
        "finding_title": finding.title,
        "finding_severity": finding.severity.value,
        "finding_status": finding.status.value,
        "subject_type": finding.subject_type.value,
        "subject_id": finding.subject_id,
        "depth": radius["depth"],
        "blast_radius": radius,
        "subgraph": subgraph,
        "attack_path": path,
        "findings_truncated": radius["open_finding_count"] > len(radius["findings"]),
        "subgraph_truncated": bool(subgraph.get("truncated")),
    }


def blast_radius_findings_csv_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten export payload findings for CSV incident handoff."""
    source_id = payload.get("finding_id")
    rows: list[dict[str, Any]] = []
    for f in payload.get("blast_radius", {}).get("findings", []):
        rows.append(
            {
                "source_finding_id": source_id,
                "finding_id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
                "status": f["status"],
                "subject_type": f["subject_type"],
                "subject_id": f["subject_id"],
                "subject_label": f.get("subject_label") or "",
                "last_seen_at": f["last_seen_at"],
                "depth": payload.get("depth"),
            }
        )
    return rows
