// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import {
  Background,
  MarkerType,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type EdgeMouseHandler,
  type MiniMapNodeProps,
  type Node,
  type NodeMouseHandler,
} from "@xyflow/react";
import { Maximize2, Minus, Plus } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import "@xyflow/react/dist/style.css";

import { ExploreGraphEdge } from "@/components/explore/explore-graph-edge";
import { ExploreGraphNode } from "@/components/explore/explore-graph-node";
import { ExploreMinimapGlyph } from "@/components/explore/explore-node-silhouettes";
import { useResolvedTheme } from "@/hooks/use-theme";
import type { GraphLabelMode } from "@/lib/graph-edge-label";
import { layoutExploreGraph, type GraphLayoutMode } from "@/lib/graph-layout";
import { nodeTypeMeta, nodeTypeShape } from "@/lib/graph-style";
import type { GraphEdge, GraphNode, GraphReachabilityPath } from "@/lib/types";

/** Programmatic pan/zoom animations aren't covered by the global CSS reduced-motion
 * override (they run through d3-zoom, not CSS transitions), so gate them explicitly. */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function motionDuration(ms: number): number {
  return prefersReducedMotion() ? 0 : ms;
}

function CanvasControlButton({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="flex size-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
    >
      {children}
    </button>
  );
}

/** Instrument-panel zoom/fit cluster — replaces the default library Controls chrome. */
function CanvasControls() {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  return (
    <Panel position="bottom-left" className="!m-3">
      <div
        role="group"
        aria-label="Canvas view controls"
        className="flex items-center gap-0.5 rounded-lg border border-border bg-elevated p-1 text-elevated-foreground shadow-md"
      >
        <CanvasControlButton label="Zoom in" onClick={() => zoomIn({ duration: motionDuration(150) })}>
          <Plus className="size-4" aria-hidden />
        </CanvasControlButton>
        <CanvasControlButton label="Zoom out" onClick={() => zoomOut({ duration: motionDuration(150) })}>
          <Minus className="size-4" aria-hidden />
        </CanvasControlButton>
        <div className="mx-0.5 h-5 w-px bg-border" aria-hidden />
        <CanvasControlButton
          label="Fit to view"
          onClick={() => fitView({ padding: 0.24, duration: motionDuration(200) })}
        >
          <Maximize2 className="size-4" aria-hidden />
        </CanvasControlButton>
      </div>
    </Panel>
  );
}

const nodeTypes = { explore: ExploreGraphNode };
const edgeTypes = { explore: ExploreGraphEdge };

function makeMiniMapNode(nodeTypeById: Map<string, string>) {
  return function ExploreMiniMapNode({
    id,
    x,
    y,
    width,
    height,
    color,
  }: MiniMapNodeProps) {
    const nodeType = nodeTypeById.get(id) ?? "setting";
    return (
      <ExploreMinimapGlyph
        shape={nodeTypeShape(nodeType)}
        color={color ?? nodeTypeMeta(nodeType).accent}
        x={x}
        y={y}
        width={width}
        height={height}
      />
    );
  };
}

function permissionByTarget(
  edges: GraphEdge[],
): Map<string, string> {
  const map = new Map<string, string>();
  for (const e of edges) {
    const level = e.properties?.permission_level;
    if (typeof level === "string" && level.trim()) {
      // Prefer admin over weaker labels when multiple edges land on one resource.
      const existing = map.get(e.target_node_id);
      const rank = { admin: 3, write: 2, read: 1 } as Record<string, number>;
      if (!existing || (rank[level] ?? 0) > (rank[existing] ?? 0)) {
        map.set(e.target_node_id, level.trim());
      }
    }
  }
  return map;
}

function explanationByEdgeId(path: GraphReachabilityPath | null): Map<string, string> {
  const map = new Map<string, string>();
  if (!path) return map;
  for (const hop of path.hops) {
    if (hop.explanation) map.set(hop.edge_id, hop.explanation);
  }
  return map;
}

function toFlow(
  nodes: GraphNode[],
  edges: GraphEdge[],
  options: {
    focusNodeId: string;
    direction: "out" | "in" | "both";
    layout: GraphLayoutMode;
    labelMode: GraphLabelMode;
    highlightedNodeIds: Set<string>;
    highlightedEdgeIds: Set<string>;
    pathHighlightActive: boolean;
    highlightedPath: GraphReachabilityPath | null;
  },
): { nodes: Node[]; edges: Edge[] } {
  const {
    focusNodeId,
    direction,
    layout,
    labelMode,
    highlightedNodeIds,
    highlightedEdgeIds,
    pathHighlightActive,
    highlightedPath,
  } = options;
  const permissions = permissionByTarget(edges);
  const explanations = explanationByEdgeId(highlightedPath);

  const flowNodes: Node[] = nodes.map((n) => ({
    id: n.id,
    type: "explore",
    position: { x: 0, y: 0 },
    data: {
      label: n.label,
      nodeType: n.node_type,
      objectId: n.object_id,
      properties: n.properties,
      permissionChip:
        n.node_type === "resource" || n.node_type === "oauth_application"
          ? permissions.get(n.id) ?? null
          : null,
      isFocus: n.id === focusNodeId || Boolean(n.is_start),
      highlighted: pathHighlightActive && highlightedNodeIds.has(n.id),
      dimmed: pathHighlightActive && !highlightedNodeIds.has(n.id),
    },
  }));

  const flowEdges: Edge[] = edges.map((e) => ({
    id: e.id,
    source: e.source_node_id,
    target: e.target_node_id,
    type: "explore",
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 16,
      height: 16,
      color: pathHighlightActive && highlightedEdgeIds.has(e.id) ? "#c026d3" : "#94a3b8",
    },
    data: {
      edgeType: e.edge_type,
      accessPath: e.access_path,
      properties: e.properties ?? {},
      explanation: explanations.get(e.id) ?? null,
      labelMode,
      highlighted: pathHighlightActive && highlightedEdgeIds.has(e.id),
      dimmed: pathHighlightActive && !highlightedEdgeIds.has(e.id),
    },
  }));

  return layoutExploreGraph(flowNodes, flowEdges, { focusNodeId, direction, mode: layout });
}

function GraphInner({
  graphNodes,
  graphEdges,
  focusNodeId,
  direction,
  layout,
  labelMode,
  highlightedPath,
  onSelectNode,
  onSelectEdge,
}: {
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  focusNodeId: string;
  direction: "out" | "in" | "both";
  layout: GraphLayoutMode;
  labelMode: GraphLabelMode;
  highlightedPath: GraphReachabilityPath | null;
  onSelectNode: (nodeId: string | null, objectId?: string, nodeType?: string) => void;
  onSelectEdge: (edgeId: string | null) => void;
}) {
  const { fitView } = useReactFlow();
  const lastFittedKey = useRef<string>("");
  const colorMode = useResolvedTheme();

  const nodeTypeById = useMemo(() => {
    const map = new Map<string, string>();
    for (const n of graphNodes) map.set(n.id, n.node_type);
    return map;
  }, [graphNodes]);

  const miniMapNode = useMemo(() => makeMiniMapNode(nodeTypeById), [nodeTypeById]);

  const highlightedNodeIds = useMemo(() => {
    if (!highlightedPath) return new Set<string>();
    const ids = new Set<string>([focusNodeId, highlightedPath.destination.id]);
    for (const hop of highlightedPath.hops) {
      ids.add(hop.from.id);
      ids.add(hop.to.id);
    }
    return ids;
  }, [highlightedPath, focusNodeId]);

  const highlightedEdgeIds = useMemo(() => {
    if (!highlightedPath) return new Set<string>();
    return new Set(highlightedPath.hops.map((h) => h.edge_id));
  }, [highlightedPath]);

  // Stable key so we only re-layout when the graph payload actually changes —
  // not on every parent re-render from the inspect panel.
  const layoutKey = useMemo(() => {
    const pathKey = highlightedPath
      ? `${highlightedPath.destination.id}:${highlightedPath.hop_count}`
      : "";
    return [
      focusNodeId,
      direction,
      layout,
      labelMode,
      pathKey,
      graphNodes.map((n) => n.id).join(","),
      graphEdges.map((e) => `${e.id}:${JSON.stringify(e.properties ?? {})}`).join(","),
    ].join("|");
  }, [focusNodeId, direction, layout, labelMode, highlightedPath, graphNodes, graphEdges]);

  const laidOut = useMemo(
    () =>
      toFlow(graphNodes, graphEdges, {
        focusNodeId,
        direction,
        layout,
        labelMode,
        highlightedNodeIds,
        highlightedEdgeIds,
        pathHighlightActive: Boolean(highlightedPath),
        highlightedPath,
      }),
    // layoutKey already encodes the inputs that affect geometry/highlights.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [layoutKey],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(laidOut.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(laidOut.edges);

  useEffect(() => {
    setNodes(laidOut.nodes);
    setEdges(laidOut.edges);
    if (lastFittedKey.current === layoutKey) return;
    lastFittedKey.current = layoutKey;
    const t = window.setTimeout(() => {
      fitView({ padding: 0.24, duration: motionDuration(200) });
    }, 50);
    return () => window.clearTimeout(t);
    // Intentionally omit fitView — its identity churned and re-fired this effect
    // in a tight loop (thousands of context API calls → 429 rate limit).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutKey, laidOut, setNodes, setEdges]);

  const onNodeClick: NodeMouseHandler = (_event, node) => {
    const data = node.data as { objectId?: string; nodeType?: string };
    onSelectEdge(null);
    onSelectNode(node.id, data.objectId, data.nodeType);
  };

  const onEdgeClick: EdgeMouseHandler = (_event, edge) => {
    onSelectNode(null);
    onSelectEdge(edge.id);
  };

  const onPaneClick = () => {
    onSelectNode(null);
    onSelectEdge(null);
  };

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onEdgeClick={onEdgeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView
      minZoom={0.2}
      maxZoom={1.75}
      proOptions={{ hideAttribution: true }}
      defaultEdgeOptions={{ animated: false }}
      colorMode={colorMode}
      className="bg-background"
    >
      <Background gap={18} size={1} color="hsl(var(--chart-grid))" />
      <CanvasControls />
      <MiniMap
        className="!border-border !bg-elevated !shadow-md"
        nodeStrokeWidth={2}
        pannable
        zoomable
        nodeComponent={miniMapNode}
        nodeColor={(n) => {
          const t = (n.data as { nodeType?: string } | undefined)?.nodeType;
          return nodeTypeMeta(t || "setting").accent;
        }}
      />
    </ReactFlow>
  );
}

export function ExploreGraphCanvas(props: {
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  focusNodeId: string;
  direction: "out" | "in" | "both";
  layout: GraphLayoutMode;
  labelMode: GraphLabelMode;
  highlightedPath: GraphReachabilityPath | null;
  onSelectNode: (nodeId: string | null, objectId?: string, nodeType?: string) => void;
  onSelectEdge: (edgeId: string | null) => void;
}) {
  return (
    <ReactFlowProvider>
      <div className="h-full w-full">
        <GraphInner {...props} />
      </div>
    </ReactFlowProvider>
  );
}
