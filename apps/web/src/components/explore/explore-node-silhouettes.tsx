// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import {
  AppWindow,
  Box,
  Key,
  KeyRound,
  Settings,
  Shield,
  User,
  Users,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import type { NodeIconName, NodeShape, NodeTypeMeta } from "@/lib/graph-style";

const ICON_MAP: Record<NodeIconName, LucideIcon> = {
  user: User,
  users: Users,
  shield: Shield,
  app_window: AppWindow,
  key_round: KeyRound,
  box: Box,
  key: Key,
  settings: Settings,
};

const VIEW = 48;

/** Path / geometry for each silhouette in a 48×48 viewBox. */
function SilhouettePath({
  shape,
  fill,
  stroke,
  strokeWidth,
}: {
  shape: NodeShape;
  fill: string;
  stroke: string;
  strokeWidth: number;
}) {
  const common = {
    fill,
    stroke,
    strokeWidth,
    strokeLinejoin: "round" as const,
  };

  switch (shape) {
    case "circle":
      return <circle cx={24} cy={24} r={20} {...common} />;
    case "hexagon":
      return <polygon points="24,4 42,14 42,34 24,44 6,34 6,14" {...common} />;
    case "shield":
      return (
        <path
          d="M24 4 L40 10 L40 24 C40 34 32 41 24 44 C16 41 8 34 8 24 L8 10 Z"
          {...common}
        />
      );
    case "rounded_square":
      return <rect x={6} y={6} width={36} height={36} rx={8} ry={8} {...common} />;
    case "cloud":
      return (
        <path
          d="M14 36 H36 C41 36 44 32.5 44 28.5 C44 24.5 41 21 37 21 C36.5 15.5 32 11 26 11 C21.5 11 17.5 13.5 15.5 17.5 C11.5 18 8 21.5 8 26 C8 31.5 11 36 14 36 Z"
          {...common}
        />
      );
    case "cylinder":
      return (
        <g>
          <ellipse cx={24} cy={12} rx={16} ry={6} {...common} />
          <path d="M8 12 V34 C8 37.3 15.2 40 24 40 C32.8 40 40 37.3 40 34 V12" {...common} />
          <ellipse
            cx={24}
            cy={34}
            rx={16}
            ry={6}
            fill="none"
            stroke={stroke}
            strokeWidth={strokeWidth}
          />
        </g>
      );
    case "diamond":
      return <polygon points="24,4 44,24 24,44 4,24" {...common} />;
    case "octagon":
      return (
        <polygon points="16,5 32,5 43,16 43,32 32,43 16,43 5,32 5,16" {...common} />
      );
  }
}

export function ExploreNodeGlyph({
  meta,
  size = 48,
  emphasized = false,
  selected = false,
  className,
  /** Replace the Lucide inner icon (e.g. vendor mark for application / OAuth). */
  innerIcon,
  /** Corner badge overlay (e.g. vendor mark on identity / role / resource). */
  badge,
}: {
  meta: NodeTypeMeta;
  size?: number;
  emphasized?: boolean;
  selected?: boolean;
  className?: string;
  innerIcon?: ReactNode;
  badge?: ReactNode;
}) {
  const strokeWidth = emphasized ? 3 : selected ? 2.5 : 2;
  const Icon = ICON_MAP[meta.icon];
  const iconSize = Math.round(size * 0.38);

  return (
    <div
      className={`relative shrink-0 ${className ?? ""}`}
      style={{ width: size, height: size }}
      aria-hidden
    >
      {(emphasized || selected) && (
        <svg
          className="pointer-events-none absolute inset-0"
          width={size}
          height={size}
          viewBox={`0 0 ${VIEW} ${VIEW}`}
        >
          <SilhouettePath
            shape={meta.shape}
            fill="none"
            stroke={emphasized ? "hsl(var(--foreground))" : "#0ea5e9"}
            strokeWidth={emphasized ? 4.5 : 4}
          />
        </svg>
      )}
      {/* Light + dark fills as twin layers so SSR/client stay in sync (no theme hook). */}
      <svg width={size} height={size} viewBox={`0 0 ${VIEW} ${VIEW}`} className="block dark:hidden">
        <SilhouettePath
          shape={meta.shape}
          fill={meta.fill}
          stroke={meta.accent}
          strokeWidth={strokeWidth}
        />
      </svg>
      <svg width={size} height={size} viewBox={`0 0 ${VIEW} ${VIEW}`} className="hidden dark:block">
        <SilhouettePath
          shape={meta.shape}
          fill={meta.fillDark}
          stroke={meta.accent}
          strokeWidth={strokeWidth}
        />
      </svg>
      <span
        className={`pointer-events-none absolute inset-0 flex items-center justify-center ${meta.text}`}
      >
        {innerIcon ?? (
          <Icon style={{ width: iconSize, height: iconSize }} strokeWidth={2.25} />
        )}
      </span>
      {badge}
    </div>
  );
}

/** Compact MiniMap glyph — fill-only silhouette at small scale. */
export function ExploreMinimapGlyph({
  shape,
  color,
  x,
  y,
  width,
  height,
}: {
  shape: NodeShape;
  color: string;
  x: number;
  y: number;
  width: number;
  height: number;
}) {
  const glyphH = Math.min(width, height * 0.55);
  const glyphW = glyphH;
  const ox = x + (width - glyphW) / 2;
  const oy = y + 2;

  return (
    <svg x={ox} y={oy} width={glyphW} height={glyphH} viewBox={`0 0 ${VIEW} ${VIEW}`}>
      <SilhouettePath shape={shape} fill={color} stroke={color} strokeWidth={1.5} />
    </svg>
  );
}
