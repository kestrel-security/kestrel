// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  FINDING_WINDOW_OPTIONS,
  GROUP_BY_OPTIONS,
  VIZ_OPTIONS,
  boardQueryKey,
  boardQuerySpec,
  boardQueryTargets,
  buildWidgetQuerySpec,
  widgetWindowLabel,
} from "./widget-query";

const base = { groupBy: "severity", status: "open", viz: "bar", findingWindow: "any", trendRange: "7d" };

describe("buildWidgetQuerySpec", () => {
  it("adds no time window to a finding widget unless one is picked", () => {
    expect(buildWidgetQuerySpec({ ...base, entity: "finding" })).toEqual({
      entity: "finding",
      filters: [{ field: "status", op: "eq", value: "open" }],
      group_by: ["severity"],
      metric: { fn: "count", field: "*" },
      limit: 20,
    });
  });

  it("matches the open-by-severity preset when configured the same way", () => {
    // presets.py's open_by_severity has no time_range either.
    const spec = buildWidgetQuerySpec({ ...base, entity: "finding" });
    expect(spec).not.toHaveProperty("time_range");
  });

  it("stores a window the author picked", () => {
    expect(
      buildWidgetQuerySpec({ ...base, entity: "finding", findingWindow: "24h" }).time_range,
    ).toEqual({ field: "opened_at", last: "1d" });
  });

  it("drops the status filter when it is blank", () => {
    const spec = buildWidgetQuerySpec({ ...base, entity: "finding", status: "  " });
    expect(spec.filters).toEqual([]);
  });

  it("never sends finding-only fields for connectors", () => {
    expect(
      buildWidgetQuerySpec({ ...base, entity: "connector", groupBy: "health", findingWindow: "7d" }),
    ).toEqual({
      entity: "connector",
      filters: [],
      group_by: ["health"],
      limit: 20,
    });
  });

  it("asks for an ungrouped count for KPI tiles", () => {
    const spec = buildWidgetQuerySpec({ ...base, entity: "connector", viz: "kpi" });
    expect(spec.group_by).toEqual([]);
  });

  it("maps the 24h range to one day for the posture trend", () => {
    expect(buildWidgetQuerySpec({ ...base, entity: "posture_trend", trendRange: "24h" })).toEqual({
      entity: "posture_trend",
      time_range: { last: "1d" },
    });
  });
});

describe("boardQuerySpec", () => {
  it("runs finding widgets exactly as stored, whatever the header says", () => {
    const unwindowed = { entity: "finding", group_by: ["severity"] };
    expect(boardQuerySpec(unwindowed, "7d")).toEqual(unwindowed);
    const windowed = { entity: "finding", time_range: { field: "opened_at", last: "30d" } };
    expect(boardQuerySpec(windowed, "7d")).toEqual(windowed);
  });

  it("points posture trends at the header range", () => {
    expect(boardQuerySpec({ entity: "posture_trend", time_range: { last: "30d" } }, "90d")).toEqual({
      entity: "posture_trend",
      time_range: { last: "90d" },
    });
  });
});

describe("widgetWindowLabel", () => {
  it("says All time for a finding widget without a window", () => {
    expect(widgetWindowLabel({ entity: "finding" }, "30d")).toBe("All time");
  });

  it("names a finding widget's own window", () => {
    expect(widgetWindowLabel({ entity: "finding", time_range: { last: "30d" } }, "7d")).toBe(
      "First seen in the last 30 days",
    );
    expect(widgetWindowLabel({ entity: "finding", time_range: { last: "1d" } }, "7d")).toBe(
      "First seen in the last 24 hours",
    );
  });

  it("names the header range for a posture trend", () => {
    expect(widgetWindowLabel({ entity: "posture_trend" }, "24h")).toBe("Last 24 hours");
    expect(widgetWindowLabel({ entity: "posture_trend" }, "90d")).toBe("Last 90 days");
  });

  it("says nothing for connectors and presets", () => {
    expect(widgetWindowLabel({ entity: "connector" }, "7d")).toBeNull();
    expect(widgetWindowLabel({ preset: "summary_metrics" }, "7d")).toBeNull();
    expect(widgetWindowLabel(null, "7d")).toBeNull();
  });
});

describe("options", () => {
  it("offers a group-by and a visualization for every grouped entity", () => {
    expect(GROUP_BY_OPTIONS.finding.length).toBeGreaterThan(0);
    expect(GROUP_BY_OPTIONS.connector.length).toBeGreaterThan(0);
    expect(GROUP_BY_OPTIONS.posture_trend).toEqual([]);
    expect(VIZ_OPTIONS.posture_trend.map((o) => o.value)).toEqual(["line", "area"]);
  });

  it("defaults finding widgets to no window", () => {
    expect(FINDING_WINDOW_OPTIONS[0]).toEqual({ value: "any", label: "Any time" });
  });
});

describe("boardQueryTargets / boardQueryKey", () => {
  const widgets = [
    { id: "a", viz_type: "bar", query_spec: { entity: "finding", group_by: "severity" }, layout: { x: 0 } },
    { id: "b", viz_type: "line", query_spec: { entity: "posture_trend" }, layout: { x: 6 } },
    { id: "c", viz_type: "markdown", query_spec: {}, layout: { x: 0 } },
    { id: "d", viz_type: "preset", query_spec: { preset: "first_run" }, layout: { x: 0 } },
    { id: "e", viz_type: "kpi", query_spec: { preset: "open_findings" }, layout: { x: 0 } },
  ];

  it("keeps only widgets that run a query, with the board's spec", () => {
    const targets = boardQueryTargets(widgets, "7d");
    expect(targets.map((t) => t.id)).toEqual(["a", "b"]);
    expect(targets[1].spec.time_range).toEqual({ last: "7d" });
  });

  it("ignores layout-only changes", () => {
    const moved = widgets.map((w) => ({ ...w, layout: { x: 3 } }));
    expect(boardQueryKey(boardQueryTargets(moved, "7d"))).toBe(
      boardQueryKey(boardQueryTargets(widgets, "7d")),
    );
  });

  it("changes with the query, the widget set or the range", () => {
    const key = boardQueryKey(boardQueryTargets(widgets, "7d"));
    expect(boardQueryKey(boardQueryTargets(widgets, "30d"))).not.toBe(key);
    expect(boardQueryKey(boardQueryTargets(widgets.slice(1), "7d"))).not.toBe(key);
    const edited = widgets.map((w) =>
      w.id === "a" ? { ...w, query_spec: { entity: "finding", group_by: "status" } } : w,
    );
    expect(boardQueryKey(boardQueryTargets(edited, "7d"))).not.toBe(key);
  });
});
