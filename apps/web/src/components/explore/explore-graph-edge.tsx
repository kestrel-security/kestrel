// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type EdgeProps,
} from "@xyflow/react";
import { memo } from "react";

import {
  compactEdgeLabel,
  edgeHoverText,
  type GraphLabelMode,
} from "@/lib/graph-edge-label";
import { accessPathMeta } from "@/lib/graph-style";

export type ExploreEdgeData = {
  edgeType: string;
  accessPath: string | null;
  properties?: Record<string, unknown>;
  explanation?: string | null;
  labelMode?: GraphLabelMode;
  highlighted?: boolean;
  dimmed?: boolean;
};

function ExploreGraphEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  markerEnd,
}: EdgeProps) {
  const edgeData = (data || {}) as ExploreEdgeData;
  const meta = accessPathMeta(edgeData.accessPath);
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });

  const width = edgeData.highlighted ? meta.width + 1.5 : meta.width;
  const opacity = edgeData.dimmed ? 0.2 : edgeData.highlighted ? 1 : 0.85;
  const labelMode: GraphLabelMode = edgeData.labelMode ?? "compact";
  const label = compactEdgeLabel(edgeData.edgeType, edgeData.properties);
  const title = edgeHoverText({
    edgeType: edgeData.edgeType,
    accessPath: edgeData.accessPath,
    properties: edgeData.properties,
    explanation: edgeData.explanation,
  });
  const showLabel =
    labelMode === "compact" || (labelMode === "hover" && edgeData.highlighted);

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke: meta.stroke,
          strokeWidth: width,
          strokeDasharray: meta.dash,
          opacity,
          filter: edgeData.dimmed ? "grayscale(1)" : undefined,
        }}
      />
      {showLabel && (
        <EdgeLabelRenderer>
          <div
            className={`nodrag nopan pointer-events-auto absolute max-w-[140px] truncate rounded border border-border bg-elevated px-1.5 py-0.5 text-[9px] font-medium text-elevated-foreground shadow-sm ${edgeData.dimmed ? "grayscale" : ""}`}
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              opacity: edgeData.dimmed ? 0.2 : 1,
            }}
            title={title}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
      {!showLabel && labelMode === "hover" && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-auto absolute h-4 w-4 -translate-x-1/2 -translate-y-1/2"
            style={{ left: labelX, top: labelY, opacity: 0 }}
            title={title}
          />
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const ExploreGraphEdge = memo(ExploreGraphEdgeComponent);
