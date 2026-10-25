// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { ExploreWorkbench } from "@/components/explore/explore-workbench";
import { apiStatePage } from "@/components/api-state";
import { ApiError, api, segment } from "@/lib/api";
import type { GraphLabelMode } from "@/lib/graph-edge-label";
import type { GraphLayoutMode } from "@/lib/graph-layout";
import type {
  GraphNeighborsResponse,
  GraphNode,
  GraphNodeContext,
  GraphReachabilityResponse,
} from "@/lib/types";

const DEPTHS = [1, 2, 3, 4, 5, 6] as const;
const DIRECTIONS = ["out", "in", "both"] as const;
const LAYOUTS = ["hierarchical", "free"] as const;
const LABEL_MODES = ["compact", "hover", "off"] as const;

function appendFilterParams(
  base: string,
  nodeTypes?: string,
  accessPaths?: string,
): string {
  const params = new URLSearchParams();
  if (nodeTypes) params.set("node_types", nodeTypes);
  if (accessPaths) params.set("access_paths", accessPaths);
  const qs = params.toString();
  if (!qs) return base;
  return base.includes("?") ? `${base}&${qs}` : `${base}?${qs}`;
}

export default async function ExplorePage({
  searchParams,
}: {
  searchParams: Promise<{
    focus?: string;
    focus_type?: string;
    direction?: string;
    depth?: string;
    layout?: string;
    labels?: string;
    node_types?: string;
    access_paths?: string;
  }>;
}) {
  const {
    focus,
    focus_type,
    direction: directionRaw,
    depth: depthRaw,
    layout: layoutRaw,
    labels: labelsRaw,
    node_types: nodeTypes,
    access_paths: accessPaths,
  } = await searchParams;

  const direction = DIRECTIONS.includes(directionRaw as (typeof DIRECTIONS)[number])
    ? (directionRaw as "out" | "in" | "both")
    : "out";
  const depthNum = Number(depthRaw);
  const depth = DEPTHS.includes(depthNum as (typeof DEPTHS)[number]) ? depthNum : 3;
  const layout: GraphLayoutMode = LAYOUTS.includes(layoutRaw as (typeof LAYOUTS)[number])
    ? (layoutRaw as GraphLayoutMode)
    : "hierarchical";
  const labelMode: GraphLabelMode = LABEL_MODES.includes(
    labelsRaw as (typeof LABEL_MODES)[number],
  )
    ? (labelsRaw as GraphLabelMode)
    : "compact";

  let start: GraphNode | null = null;
  let neighbors: GraphNeighborsResponse | null = null;
  let reach: GraphReachabilityResponse | null = null;
  let initialContext: GraphNodeContext | null = null;

  if (focus && focus_type) {
    try {
      start = await api.get<GraphNode>(
        `/graph/resolve?node_type=${encodeURIComponent(focus_type)}&object_id=${encodeURIComponent(focus)}`,
      );
      const neighborPath = appendFilterParams(
        `/graph/nodes/${segment(start.id)}/neighbors?direction=${direction}&depth=${depth}`,
        nodeTypes,
        accessPaths,
      );
      neighbors = await api.get<GraphNeighborsResponse>(neighborPath);
      // Paths API is directional (out|in) — map "both" to outbound narrative list.
      const pathDirection = direction === "in" ? "in" : "out";
      const pathsQs = new URLSearchParams({
        direction: pathDirection,
        depth: String(depth),
      });
      if (nodeTypes) pathsQs.set("destination_types", nodeTypes);
      reach = await api.get<GraphReachabilityResponse>(
        `/graph/nodes/${segment(start.id)}/paths?${pathsQs.toString()}`,
      );
      initialContext = await api.get<GraphNodeContext>(`/graph/nodes/${segment(start.id)}/context`);
    } catch (error) {
      const statePage = apiStatePage(error);
      if (statePage) return statePage;
      if (error instanceof ApiError && error.status === 429) {
        return (
          <div className="flex h-full items-center justify-center p-8">
            <div className="max-w-md rounded-lg border border-amber-300 bg-amber-50 p-6 text-center dark:border-amber-900 dark:bg-amber-950">
              <p className="text-base font-semibold text-amber-950 dark:text-amber-100">
                API rate limit reached
              </p>
              <p className="mt-2 text-sm text-amber-900 dark:text-amber-200">
                Too many graph requests fired in a short window. Wait about a minute, then refresh
                this page.
              </p>
            </div>
          </div>
        );
      }
      if (!(error instanceof ApiError && (error.status === 404 || error.status === 422))) {
        throw error;
      }
      // Fall through to empty canvas with search — invalid focus.
    }
  }

  let suggestions: {
    id: string;
    display_name: string | null;
    email: string | null;
    application_types?: string[];
    account_count?: number;
  }[] = [];
  if (!start) {
    try {
      const page = await api.get<{
        items: {
          id: string;
          display_name: string | null;
          email: string | null;
          application_types?: string[];
          account_count?: number;
        }[];
      }>("/identities?privileged=true&collapse=true&limit=8");
      suggestions = page.items;
    } catch (error) {
      const statePage = apiStatePage(error);
      if (statePage) return statePage;
    }
  }

  // Keyed on what the graph data depends on: a new focus (or traversal) is a
  // new graph, so the workbench must not carry over the previous selection,
  // inspector or in-flight fetches. Layout and label mode only restyle it.
  const workbenchKey = JSON.stringify([focus, focus_type, direction, depth, nodeTypes, accessPaths]);

  return (
    <ExploreWorkbench
      key={workbenchKey}
      focus={focus}
      focusType={focus_type}
      direction={direction}
      depth={depth}
      layout={layout}
      labelMode={labelMode}
      nodeTypes={nodeTypes}
      accessPaths={accessPaths}
      start={start}
      neighbors={neighbors}
      reach={reach}
      initialContext={initialContext}
      suggestions={suggestions}
    />
  );
}
