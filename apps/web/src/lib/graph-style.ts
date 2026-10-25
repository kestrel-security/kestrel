// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Shared visual tokens for the Explore identity graph canvas. */

export type NodeShape =
  | "circle"
  | "hexagon"
  | "shield"
  | "rounded_square"
  | "cloud"
  | "cylinder"
  | "diamond"
  | "octagon";

export type NodeIconName =
  | "user"
  | "users"
  | "shield"
  | "app_window"
  | "key_round"
  | "box"
  | "key"
  | "settings";

export type NodeTypeMeta = {
  label: string;
  short: string;
  shape: NodeShape;
  icon: NodeIconName;
  bg: string;
  border: string;
  text: string;
  /** Fill for SVG glyphs (light / dark aware via CSS vars when rendered). */
  fill: string;
  fillDark: string;
  accent: string;
};

export const NODE_TYPE_META: Record<string, NodeTypeMeta> = {
  identity: {
    label: "Identity",
    short: "ID",
    shape: "circle",
    icon: "user",
    bg: "bg-sky-50 dark:bg-sky-950/80",
    border: "border-sky-400 dark:border-sky-600",
    text: "text-sky-950 dark:text-sky-100",
    fill: "#f0f9ff",
    fillDark: "#082f49",
    accent: "#0ea5e9",
  },
  group: {
    label: "Group",
    short: "GRP",
    shape: "hexagon",
    icon: "users",
    bg: "bg-violet-50 dark:bg-violet-950/80",
    border: "border-violet-400 dark:border-violet-600",
    text: "text-violet-950 dark:text-violet-100",
    fill: "#f5f3ff",
    fillDark: "#2e1065",
    accent: "#8b5cf6",
  },
  role: {
    label: "Role",
    short: "ROLE",
    shape: "shield",
    icon: "shield",
    bg: "bg-amber-50 dark:bg-amber-950/80",
    border: "border-amber-400 dark:border-amber-600",
    text: "text-amber-950 dark:text-amber-100",
    fill: "#fffbeb",
    fillDark: "#451a03",
    accent: "#f59e0b",
  },
  resource: {
    label: "Resource",
    short: "RES",
    shape: "cylinder",
    icon: "box",
    bg: "bg-emerald-50 dark:bg-emerald-950/80",
    border: "border-emerald-400 dark:border-emerald-600",
    text: "text-emerald-950 dark:text-emerald-100",
    fill: "#ecfdf5",
    fillDark: "#022c22",
    accent: "#10b981",
  },
  oauth_application: {
    label: "OAuth app",
    short: "OAUTH",
    shape: "cloud",
    icon: "key_round",
    bg: "bg-fuchsia-50 dark:bg-fuchsia-950/80",
    border: "border-fuchsia-400 dark:border-fuchsia-600",
    text: "text-fuchsia-950 dark:text-fuchsia-100",
    fill: "#fdf4ff",
    fillDark: "#4a044e",
    accent: "#d946ef",
  },
  permission: {
    label: "Permission",
    short: "PERM",
    shape: "diamond",
    icon: "key",
    bg: "bg-slate-50 dark:bg-slate-900",
    border: "border-slate-400 dark:border-slate-600",
    text: "text-slate-900 dark:text-slate-100",
    fill: "#f8fafc",
    fillDark: "#0f172a",
    accent: "#64748b",
  },
  application: {
    label: "Application",
    short: "APP",
    shape: "rounded_square",
    icon: "app_window",
    bg: "bg-indigo-50 dark:bg-indigo-950/80",
    border: "border-indigo-400 dark:border-indigo-600",
    text: "text-indigo-950 dark:text-indigo-100",
    fill: "#eef2ff",
    fillDark: "#1e1b4b",
    accent: "#6366f1",
  },
  setting: {
    label: "Setting",
    short: "CFG",
    shape: "octagon",
    icon: "settings",
    bg: "bg-gray-50 dark:bg-gray-900",
    border: "border-gray-400 dark:border-gray-600",
    text: "text-gray-900 dark:text-gray-100",
    fill: "#f9fafb",
    fillDark: "#111827",
    accent: "#6b7280",
  },
};

/** Canonical node types for legend / uniqueness checks. */
export const KNOWN_NODE_TYPES = [
  "identity",
  "group",
  "role",
  "application",
  "oauth_application",
  "resource",
  "permission",
  "setting",
] as const;

export const ACCESS_PATH_META: Record<
  string,
  { label: string; stroke: string; dash?: string; width: number }
> = {
  direct: { label: "Direct", stroke: "#dc2626", width: 2 },
  inherited_group: { label: "Inherited (group)", stroke: "#64748b", width: 1.75 },
  // Distinct purple-slate so inherited_role is not identical to group inheritance.
  inherited_role: { label: "Inherited (role)", stroke: "#7c3aed", width: 1.75 },
  federated: { label: "Federated", stroke: "#4f46e5", width: 1.75 },
  oauth_derived: { label: "OAuth-derived", stroke: "#c026d3", dash: "6 4", width: 2.25 },
};

export const DEFAULT_ACCESS_META: {
  label: string;
  stroke: string;
  dash?: string;
  width: number;
} = {
  label: "Relationship",
  stroke: "#94a3b8",
  width: 1.5,
};

export function nodeTypeMeta(nodeType: string): NodeTypeMeta {
  return NODE_TYPE_META[nodeType] ?? NODE_TYPE_META.setting;
}

export function nodeTypeShape(nodeType: string): NodeShape {
  return nodeTypeMeta(nodeType).shape;
}

export function accessPathMeta(accessPath: string | null | undefined) {
  if (!accessPath) return DEFAULT_ACCESS_META;
  return ACCESS_PATH_META[accessPath] ?? DEFAULT_ACCESS_META;
}
