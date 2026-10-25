// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Options and spec building for custom dashboard widgets. Mirrors the
 * allowlist in kestrel/dashboard/query_dsl.py so the "Add widget" dialog can
 * only author queries the API accepts.
 *
 * Time windows: a finding widget counts every finding, like the built-in
 * presets, unless its own spec carries a `time_range` the author picked in
 * the dialog. The dashboard header's range drives posture-trend charts only.
 * The board, exports and scheduled emails all run the stored spec, so they
 * agree, and the card states its window (`widgetWindowLabel`).
 */

import { countOf } from "@/lib/plural";

export type WidgetEntity = "finding" | "connector" | "posture_trend";

type Option = { value: string; label: string };

export const WIDGET_ENTITIES: { value: WidgetEntity; label: string }[] = [
  { value: "finding", label: "Finding" },
  { value: "connector", label: "Integration" },
  { value: "posture_trend", label: "Posture trend" },
];

export const GROUP_BY_OPTIONS: Record<WidgetEntity, Option[]> = {
  finding: [
    { value: "severity", label: "Severity" },
    { value: "status", label: "Status" },
    { value: "subject_type", label: "Subject type" },
  ],
  connector: [
    { value: "health", label: "Health" },
    { value: "sync_mode", label: "Sync mode" },
  ],
  posture_trend: [],
};

export const VIZ_OPTIONS: Record<WidgetEntity, Option[]> = {
  finding: [
    { value: "bar", label: "Bar" },
    { value: "pie", label: "Pie" },
    { value: "donut", label: "Donut" },
    { value: "kpi", label: "KPI" },
    { value: "table", label: "Table" },
  ],
  connector: [
    { value: "bar", label: "Bar" },
    { value: "pie", label: "Pie" },
    { value: "donut", label: "Donut" },
    { value: "kpi", label: "KPI" },
    { value: "table", label: "Table" },
  ],
  posture_trend: [
    { value: "line", label: "Line" },
    { value: "area", label: "Area" },
  ],
};

/** "First seen within" choices for a finding widget; "any" stores no window (Radix Select has no empty value). */
export const FINDING_WINDOW_OPTIONS: Option[] = [
  { value: "any", label: "Any time" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

export type WidgetQueryInput = {
  entity: WidgetEntity;
  groupBy: string;
  /** Finding status filter; ignored for other entities. Empty means any status. */
  status: string;
  viz: string;
  /** Finding widgets only: "first seen within" window; "any" or "" for none. */
  findingWindow: string;
  /** Posture trend only: the dashboard header's range ("24h", "7d", ...). */
  trendRange: string;
};

/** The DSL counts days and hours; the dashboard's "24h" maps to one day. */
function toQueryLast(timeRange: string): string {
  return timeRange === "24h" ? "1d" : timeRange;
}

export function buildWidgetQuerySpec(input: WidgetQueryInput): Record<string, unknown> {
  if (input.entity === "posture_trend") {
    return { entity: "posture_trend", time_range: { last: toQueryLast(input.trendRange) } };
  }
  const groupBy = input.viz === "kpi" ? [] : [input.groupBy];
  if (input.entity === "connector") {
    return { entity: "connector", filters: [], group_by: groupBy, limit: 20 };
  }
  const status = input.status.trim();
  const spec: Record<string, unknown> = {
    entity: "finding",
    filters: status ? [{ field: "status", op: "eq", value: status }] : [],
    group_by: groupBy,
    metric: { fn: "count", field: "*" },
    limit: 20,
  };
  if (input.findingWindow && input.findingWindow !== "any") {
    spec.time_range = { field: "opened_at", last: toQueryLast(input.findingWindow) };
  }
  return spec;
}

/**
 * The spec the board runs for a stored widget: posture trends follow the
 * header range; everything else runs exactly as stored.
 */
export function boardQuerySpec(
  spec: Record<string, unknown>,
  headerRange: string,
): Record<string, unknown> {
  if (spec.entity === "posture_trend") {
    return { ...spec, time_range: { last: toQueryLast(headerRange) } };
  }
  return spec;
}

const NON_QUERY_VIZ = new Set(["preset", "markdown", "list"]);

export type BoardQueryTarget = { id: string; spec: Record<string, unknown> };

/** The widgets whose cards run a dashboard query, each with the spec the board sends. */
export function boardQueryTargets(
  widgets: { id: string; viz_type: string; query_spec?: Record<string, unknown> | null }[],
  headerRange: string,
): BoardQueryTarget[] {
  return widgets
    .filter((w) => !NON_QUERY_VIZ.has(w.viz_type) && w.query_spec && !w.query_spec.preset)
    .map((w) => ({ id: w.id, spec: boardQuerySpec(w.query_spec as Record<string, unknown>, headerRange) }));
}

/**
 * A stable identity for what the board would fetch. Dragging or resizing a
 * card creates new widget objects but leaves this unchanged, so previews are
 * not re-run for layout edits.
 */
export function boardQueryKey(targets: BoardQueryTarget[]): string {
  return JSON.stringify(targets.map((t) => [t.id, t.spec]));
}

/** "7d" → "7 days", "1d" or "24h" → "24 hours"; null when the DSL wouldn't accept it. */
function describeLast(last: string): string | null {
  const match = /^(\d+)([dh])$/.exec(last.trim().toLowerCase());
  if (!match) return null;
  const n = Number(match[1]);
  if (match[2] === "d" && n === 1) return "24 hours";
  return countOf(n, match[2] === "d" ? "day" : "hour");
}

/**
 * What a widget card says about its time window: the trend's range, a
 * finding widget's own window, "All time" for a finding widget without one,
 * or null where windows don't apply (connectors, presets, notes).
 */
export function widgetWindowLabel(
  spec: Record<string, unknown> | null | undefined,
  headerRange: string,
): string | null {
  if (!spec || spec.preset) return null;
  if (spec.entity === "posture_trend") {
    const range = describeLast(toQueryLast(headerRange));
    return range ? `Last ${range}` : null;
  }
  if (spec.entity !== "finding") return null;
  const timeRange = spec.time_range as { last?: unknown } | null | undefined;
  if (typeof timeRange?.last === "string") {
    const window = describeLast(timeRange.last);
    if (window) return `First seen in the last ${window}`;
  }
  return "All time";
}
