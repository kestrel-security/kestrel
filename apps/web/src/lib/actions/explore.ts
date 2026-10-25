// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { GraphEdgeContext, GraphNodeContext, GraphSearchItem, GraphSearchResponse } from "@/lib/types";

/** Graph node investigation panel. */
export async function fetchGraphNodeContext(
  nodeId: string,
): Promise<
  | { ok: true; context: GraphNodeContext }
  | { ok: false; error: string }
> {
  try {
    const context = await api.get<GraphNodeContext>(
      `/graph/nodes/${segment(nodeId)}/context`,
    );
    return { ok: true, context };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Explore picker search. */
export async function searchGraphNodes(
  q: string,
  nodeTypes?: string,
): Promise<
  | { ok: true; items: GraphSearchItem[] }
  | { ok: false; error: string }
> {
  try {
    const query = new URLSearchParams({ q });
    if (nodeTypes) query.set("node_types", nodeTypes);
    const body = await api.get<GraphSearchResponse>(
      `/graph/search?${query.toString()}`,
    );
    return { ok: true, items: body.items };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Graph edge explainability panel. */
export async function fetchGraphEdgeContext(
  edgeId: string,
): Promise<
  | { ok: true; context: GraphEdgeContext }
  | { ok: false; error: string }
> {
  try {
    const context = await api.get<GraphEdgeContext>(
      `/graph/edges/${segment(edgeId)}`,
    );
    return { ok: true, context };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
