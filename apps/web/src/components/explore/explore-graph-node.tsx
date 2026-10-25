// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";

import { AppMark, AppMarkBadge, AppMarkStack } from "@/components/brand/app-mark";
import { ExploreNodeGlyph } from "@/components/explore/explore-node-silhouettes";
import {
  resolveAppMarkFromNode,
  resolveAppMarksFromTypes,
} from "@/lib/app-mark";
import { nodeChipLabel } from "@/lib/graph-edge-label";
import { nodeTypeMeta } from "@/lib/graph-style";

export const EXPLORE_NODE_GLYPH_SIZE = 48;
export const EXPLORE_NODE_CAPTION_WIDTH = 120;

export type ExploreNodeData = {
  label: string;
  nodeType: string;
  objectId: string;
  properties?: Record<string, unknown>;
  /** Incoming can_access permission when this node is a resource. */
  permissionChip?: string | null;
  isFocus?: boolean;
  dimmed?: boolean;
  highlighted?: boolean;
};

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.trim().length > 0);
}

function ExploreGraphNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as ExploreNodeData;
  const meta = nodeTypeMeta(nodeData.nodeType);
  const dimClasses = nodeData.dimmed ? "opacity-35 grayscale" : "opacity-100";
  const glyphMidY = EXPLORE_NODE_GLYPH_SIZE / 2;
  const chip =
    nodeData.permissionChip ||
    nodeChipLabel(nodeData.nodeType, nodeData.properties, null);
  const appType =
    typeof nodeData.properties?.application_type === "string"
      ? nodeData.properties.application_type.replace(/_/g, " ")
      : null;
  const titleParts = [`${nodeData.label} (${meta.label})`];
  if (chip) titleParts.push(chip);
  if (appType) titleParts.push(appType);
  const email =
    typeof nodeData.properties?.email === "string" ? nodeData.properties.email : null;
  if (email) titleParts.push(email);

  const appMark = resolveAppMarkFromNode({
    nodeType: nodeData.nodeType,
    label: nodeData.label,
    properties: nodeData.properties,
  });
  const clusterTypes = asStringArray(nodeData.properties?.application_types);
  const clusterMarks =
    nodeData.nodeType === "identity" && clusterTypes.length > 1
      ? resolveAppMarksFromTypes(clusterTypes, 3)
      : null;

  const isAppSurface =
    nodeData.nodeType === "application" || nodeData.nodeType === "oauth_application";
  const innerIconSize = Math.round(EXPLORE_NODE_GLYPH_SIZE * 0.42);
  const hasSingleApp =
    Boolean(nodeData.properties?.application_type) ||
    nodeData.nodeType === "oauth_application" ||
    nodeData.nodeType === "application";

  return (
    <div
      className={`relative flex w-[120px] flex-col items-center transition-[opacity,filter] ${dimClasses}`}
      title={titleParts.join(" · ")}
    >
      <div className="relative" style={{ width: EXPLORE_NODE_GLYPH_SIZE, height: EXPLORE_NODE_GLYPH_SIZE }}>
        <Handle
          type="target"
          position={Position.Left}
          className="!h-2 !w-2 !border-0 !bg-slate-400"
          style={{ top: glyphMidY, left: 0 }}
        />
        <ExploreNodeGlyph
          meta={meta}
          size={EXPLORE_NODE_GLYPH_SIZE}
          emphasized={Boolean(nodeData.isFocus)}
          selected={selected || Boolean(nodeData.highlighted)}
          innerIcon={
            isAppSurface ? (
              <AppMark mark={appMark} size={innerIconSize} />
            ) : undefined
          }
          badge={
            !isAppSurface && clusterMarks ? (
              <span className="pointer-events-none absolute -bottom-1 -right-1 flex max-w-[56px] items-center gap-0.5 rounded-full border border-border bg-background px-0.5 py-0.5 shadow-sm dark:bg-slate-800">
                <AppMarkStack
                  marks={clusterMarks.marks}
                  overflow={clusterMarks.overflow}
                  size={12}
                />
              </span>
            ) : !isAppSurface && hasSingleApp ? (
              <AppMarkBadge mark={appMark} size={12} />
            ) : undefined
          }
        />
        <Handle
          type="source"
          position={Position.Right}
          className="!h-2 !w-2 !border-0 !bg-slate-400"
          style={{ top: glyphMidY, right: 0 }}
        />
      </div>
      <div className="mt-1.5 w-full min-w-0 px-0.5 text-center">
        <div className={`truncate text-xs font-semibold leading-tight ${meta.text}`}>
          {nodeData.label}
        </div>
        <div className="mt-0.5 truncate text-[9px] uppercase tracking-wide text-muted-foreground">
          {meta.label}
          {nodeData.isFocus ? " · focus" : ""}
          {!nodeData.isFocus && appType ? ` · ${appType}` : ""}
        </div>
        {chip && (
          <div className="mt-0.5 truncate rounded bg-muted px-1 text-[9px] font-medium text-foreground">
            {chip}
          </div>
        )}
      </div>
    </div>
  );
}

export const ExploreGraphNode = memo(ExploreGraphNodeComponent);
