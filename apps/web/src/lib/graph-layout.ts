// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import dagre from "@dagrejs/dagre";
import { Position, type Edge, type Node } from "@xyflow/react";

/** Bounding box for glyph (~48) + caption under (~120×52). */
const NODE_WIDTH = 128;
const NODE_HEIGHT = 100;

/** Horizontal gap between hop columns (center-to-center minus node width). */
const RANKSEP = 200;
/** Vertical gap between nodes in the same hop column. */
const NODESEP = 72;

export type GraphLayoutMode = "hierarchical" | "free";
export type ExploreDirection = "out" | "in" | "both";

/** Default Explore traversal when focusing a node type. Groups sandwich
 * members (inbound) and apps (outbound) with direction=both. */
export function defaultExploreDirection(nodeType: string): ExploreDirection {
  if (nodeType === "group") {
    return "both";
  }
  if (
    nodeType === "resource" ||
    nodeType === "oauth_application" ||
    nodeType === "permission" ||
    nodeType === "setting"
  ) {
    return "in";
  }
  return "out";
}

function bfsDistances(
  startId: string,
  adjacency: Map<string, string[]>,
  nodeIds: Set<string>,
): Map<string, number> {
  const dist = new Map<string, number>();
  if (!nodeIds.has(startId)) return dist;

  const queue: string[] = [startId];
  dist.set(startId, 0);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const nextDist = (dist.get(current) ?? 0) + 1;
    for (const next of adjacency.get(current) ?? []) {
      if (!nodeIds.has(next) || dist.has(next)) continue;
      dist.set(next, nextDist);
      queue.push(next);
    }
  }
  return dist;
}

function buildAdjacency(edges: Edge[], nodeIds: Set<string>) {
  const forward = new Map<string, string[]>();
  const backward = new Map<string, string[]>();
  const undirected = new Map<string, string[]>();
  const add = (map: Map<string, string[]>, from: string, to: string) => {
    const list = map.get(from) ?? [];
    list.push(to);
    map.set(from, list);
  };

  for (const edge of edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) continue;
    add(forward, edge.source, edge.target);
    add(backward, edge.target, edge.source);
    add(undirected, edge.source, edge.target);
    add(undirected, edge.target, edge.source);
  }
  return { forward, backward, undirected };
}

/** Assign dagre ranks from the focus node so layers follow arrow direction. */
export function ranksFromFocus(
  nodeIds: Set<string>,
  edges: Edge[],
  focusNodeId: string,
  direction: ExploreDirection,
): Map<string, number> {
  const ranks = new Map<string, number>();
  if (!nodeIds.has(focusNodeId)) return ranks;

  const { forward, backward, undirected } = buildAdjacency(edges, nodeIds);

  if (direction === "both") {
    const inbound = bfsDistances(focusNodeId, backward, nodeIds);
    const outbound = bfsDistances(focusNodeId, forward, nodeIds);
    const maxInbound = Math.max(
      0,
      ...[...inbound.values()].filter((d) => d > 0),
    );
    ranks.set(focusNodeId, maxInbound);
    for (const [id, d] of inbound) {
      if (d > 0) ranks.set(id, maxInbound - d);
    }
    for (const [id, d] of outbound) {
      if (d > 0) ranks.set(id, maxInbound + d);
    }
  } else {
    const adjacency = direction === "in" ? backward : forward;
    const dist = bfsDistances(focusNodeId, adjacency, nodeIds);
    for (const [id, d] of dist) {
      ranks.set(id, d);
    }
  }

  // Nodes only reachable via mixed-direction paths still get a column so they
  // don't collapse onto the focus stack.
  if (ranks.size < nodeIds.size) {
    const undirectedDist = bfsDistances(focusNodeId, undirected, nodeIds);
    let maxRank = Math.max(0, ...ranks.values());
    for (const id of nodeIds) {
      if (ranks.has(id)) continue;
      const d = undirectedDist.get(id);
      if (d == null) {
        ranks.set(id, ++maxRank);
      } else if (direction === "both") {
        const focusRank = ranks.get(focusNodeId) ?? 0;
        // Prefer outbound side for undirected leftovers so the sandwich stays readable.
        ranks.set(id, focusRank + d);
      } else if (direction === "in") {
        ranks.set(id, d);
      } else {
        ranks.set(id, d);
      }
    }
  }

  return ranks;
}

function nodeLabel(node: Node): string {
  return String((node.data as { label?: string } | undefined)?.label ?? node.id);
}

/**
 * Order nodes within each hop column to reduce edge crossings (barycenter
 * heuristic). Uses neighbor order indices in adjacent columns.
 */
function orderLayersByBarycenter(
  layers: Map<number, Node[]>,
  edges: Edge[],
  maxRank: number,
): void {
  const neighbors = new Map<string, string[]>();
  const addN = (a: string, b: string) => {
    const list = neighbors.get(a) ?? [];
    list.push(b);
    neighbors.set(a, list);
  };
  for (const edge of edges) {
    addN(edge.source, edge.target);
    addN(edge.target, edge.source);
  }

  const rankOf = new Map<string, number>();
  for (const [rank, layer] of layers) {
    for (const n of layer) rankOf.set(n.id, rank);
  }

  const barycenter = (id: string, towardRank: number, orderIndex: Map<string, number>) => {
    const idxs: number[] = [];
    for (const nb of neighbors.get(id) ?? []) {
      if (rankOf.get(nb) !== towardRank) continue;
      const idx = orderIndex.get(nb);
      if (idx != null) idxs.push(idx);
    }
    if (idxs.length === 0) return orderIndex.get(id) ?? 0;
    return idxs.reduce((a, b) => a + b, 0) / idxs.length;
  };

  for (let pass = 0; pass < 4; pass++) {
    // Top-down
    for (let rank = 1; rank <= maxRank; rank++) {
      const prev = layers.get(rank - 1);
      const layer = layers.get(rank);
      if (!prev || !layer || layer.length < 2) continue;
      const orderIndex = new Map(prev.map((n, i) => [n.id, i]));
      layer.sort((a, b) => {
        const ba = barycenter(a.id, rank - 1, orderIndex);
        const bb = barycenter(b.id, rank - 1, orderIndex);
        if (ba !== bb) return ba - bb;
        return nodeLabel(a).localeCompare(nodeLabel(b));
      });
    }
    // Bottom-up
    for (let rank = maxRank - 1; rank >= 0; rank--) {
      const next = layers.get(rank + 1);
      const layer = layers.get(rank);
      if (!next || !layer || layer.length < 2) continue;
      const orderIndex = new Map(next.map((n, i) => [n.id, i]));
      layer.sort((a, b) => {
        const ba = barycenter(a.id, rank + 1, orderIndex);
        const bb = barycenter(b.id, rank + 1, orderIndex);
        if (ba !== bb) return ba - bb;
        return nodeLabel(a).localeCompare(nodeLabel(b));
      });
    }
  }
}

/** Layer nodes in columns by hop distance from focus so edges read source → target. */
function layoutByFocusRanks(
  nodes: Node[],
  edges: Edge[],
  ranks: Map<string, number>,
  direction: ExploreDirection,
): Node[] {
  const layers = new Map<number, Node[]>();
  for (const node of nodes) {
    const rank = ranks.get(node.id) ?? 0;
    const layer = layers.get(rank) ?? [];
    layer.push(node);
    layers.set(rank, layer);
  }

  for (const layer of layers.values()) {
    layer.sort((a, b) => nodeLabel(a).localeCompare(nodeLabel(b)));
  }

  const maxRank = Math.max(0, ...layers.keys());
  orderLayersByBarycenter(layers, edges, maxRank);

  const positions = new Map<string, { x: number; y: number }>();
  /** When a hop column is dense, wrap into subcolumns so the canvas stays wide. */
  const WRAP_AFTER = 6;
  const SUBCOL_GAP = NODE_WIDTH + 48;

  // A wrapped rank is wider than one node, so hop columns cannot sit on a fixed
  // pitch: a rank of three subcolumns spans 2*SUBCOL_GAP + NODE_WIDTH = 480,
  // more than the 328 a NODE_WIDTH + RANKSEP pitch would allow, and it bled
  // into the neighbouring rank until its captions collided. Measure each rank
  // first, then advance the origin by the width actually used.
  const shape = new Map<number, { perCol: number; width: number }>();
  for (const [rank, layer] of layers) {
    const subCols = layer.length > WRAP_AFTER ? Math.ceil(layer.length / WRAP_AFTER) : 1;
    shape.set(rank, {
      perCol: Math.ceil(layer.length / subCols),
      width: (subCols - 1) * SUBCOL_GAP + NODE_WIDTH,
    });
  }

  // Walk hop columns left to right, mirroring for inbound so edges still read
  // source → target, and give every rank its own left edge.
  const originX = new Map<number, number>();
  let cursor = 24;
  for (let column = 0; column <= maxRank; column++) {
    const rank = direction === "in" ? maxRank - column : column;
    const size = shape.get(rank);
    if (!size) continue;
    originX.set(rank, cursor);
    cursor += size.width + RANKSEP;
  }

  for (const [rank, layer] of layers) {
    const { perCol } = shape.get(rank)!;
    const baseX = originX.get(rank) ?? 24;

    for (let i = 0; i < layer.length; i++) {
      const node = layer[i]!;
      const sub = Math.floor(i / perCol);
      const row = i % perCol;
      const colLen = Math.min(perCol, layer.length - sub * perCol);
      const totalHeight = colLen * NODE_HEIGHT + Math.max(0, colLen - 1) * NODESEP;
      const y = -totalHeight / 2 + row * (NODE_HEIGHT + NODESEP);
      const x = baseX + sub * SUBCOL_GAP;
      positions.set(node.id, { x, y });
    }
  }

  return nodes.map((node) => ({
    ...node,
    position: positions.get(node.id) ?? { x: 0, y: 0 },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  }));
}

/** Dagre hierarchical layout — layers follow access flow from the focus node. */
export function layoutExploreGraph(
  nodes: Node[],
  edges: Edge[],
  options: {
    focusNodeId?: string;
    direction?: ExploreDirection;
    mode?: GraphLayoutMode;
  } = {},
): { nodes: Node[]; edges: Edge[] } {
  const direction = options.direction ?? "out";
  const mode = options.mode ?? "hierarchical";
  const focusNodeId = options.focusNodeId;
  if (mode === "free" || nodes.length === 0) {
    return {
      nodes: nodes.map((n, i) => ({
        ...n,
        position:
          n.position?.x || n.position?.y
            ? n.position
            : { x: (i % 6) * 180, y: Math.floor(i / 6) * 140 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      })),
      edges,
    };
  }

  const nodeIds = new Set(nodes.map((n) => n.id));
  if (focusNodeId != null && nodeIds.has(focusNodeId)) {
    const ranks = ranksFromFocus(nodeIds, edges, focusNodeId, direction);
    return {
      nodes: layoutByFocusRanks(nodes, edges, ranks, direction),
      edges,
    };
  }

  const g = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  const rankdir = direction === "in" ? "RL" : "LR";
  g.setGraph({
    rankdir,
    ranker: "longest-path",
    align: "UL",
    nodesep: NODESEP,
    ranksep: RANKSEP,
    marginx: 24,
    marginy: 24,
  });

  for (const node of nodes) {
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (const edge of edges) {
    if (g.hasNode(edge.source) && g.hasNode(edge.target)) {
      g.setEdge(edge.source, edge.target);
    }
  }

  dagre.layout(g);

  const laidOut = nodes.map((node) => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: {
        x: (pos?.x ?? 0) - NODE_WIDTH / 2,
        y: (pos?.y ?? 0) - NODE_HEIGHT / 2,
      },
      sourcePosition: rankdir === "RL" ? Position.Left : Position.Right,
      targetPosition: rankdir === "RL" ? Position.Right : Position.Left,
    };
  });

  return { nodes: laidOut, edges };
}

export const EXPLORE_NODE_WIDTH = NODE_WIDTH;
export const EXPLORE_NODE_HEIGHT = NODE_HEIGHT;
