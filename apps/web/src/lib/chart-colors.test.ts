// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  BRAND_SERIES_DOT,
  BRAND_SERIES_FILL,
  HEALTH_TONES,
  SEVERITY_TONES,
  STATUS_TONES,
  chartDotClassFor,
  chartFillClassFor,
  formatChartCategory,
  inferChartKind,
} from "./chart-colors";

// Thin adapters so the assertions read the same as the rest of the file.
const assert = {
  equal: (actual: unknown, expected: unknown) => expect(actual).toBe(expected),
  deepEqual: (actual: unknown, expected: unknown) => expect(actual).toEqual(expected),
  ok: (value: unknown) => expect(value).toBeTruthy(),
};

describe("chartFillClassFor", () => {
  it("maps severity keys to muted tone fill classes", () => {
    assert.equal(chartFillClassFor("critical", "severity"), "fill-tone-critical");
    assert.equal(chartFillClassFor("high", "severity"), "fill-tone-high");
    assert.equal(chartFillClassFor("medium", "severity"), "fill-tone-medium");
    assert.equal(chartFillClassFor("low", "severity"), "fill-tone-low");
    assert.equal(chartFillClassFor("info", "severity"), "fill-tone-info");
  });

  it("maps status keys to brand-forward fill classes (open is primary)", () => {
    assert.equal(chartFillClassFor("open", "status"), "fill-primary");
    assert.equal(chartFillClassFor("resolved", "status"), "fill-tone-success");
    assert.equal(chartFillClassFor("exception", "status"), "fill-tone-info");
    assert.equal(chartFillClassFor("muted", "status"), "fill-tone-low");
  });

  it("maps health keys semantically", () => {
    assert.equal(chartFillClassFor("healthy", "health"), "fill-tone-success");
    assert.equal(chartFillClassFor("failed", "health"), "fill-tone-critical");
    assert.equal(chartFillClassFor("never_synced", "health"), "fill-tone-neutral");
  });

  it("cycles brand series for generic data", () => {
    const a = chartFillClassFor("custom-a", "generic");
    const b = chartFillClassFor("custom-b", "generic");
    assert.ok(BRAND_SERIES_FILL.includes(a as (typeof BRAND_SERIES_FILL)[number]));
    assert.ok(BRAND_SERIES_FILL.includes(b as (typeof BRAND_SERIES_FILL)[number]));
  });

  it("infers kind from series names when kind is generic", () => {
    assert.equal(chartFillClassFor("critical"), "fill-tone-critical");
    assert.equal(chartFillClassFor("open"), "fill-primary");
    assert.equal(chartFillClassFor("healthy"), "fill-tone-success");
  });
});

describe("chartDotClassFor", () => {
  it("maps severity keys to muted tone dot classes", () => {
    assert.equal(chartDotClassFor("critical", "severity"), "bg-tone-critical");
    assert.equal(chartDotClassFor("high", "severity"), "bg-tone-high");
  });

  it("cycles brand series dots for generic data", () => {
    const a = chartDotClassFor("custom-a", "generic");
    assert.ok(BRAND_SERIES_DOT.includes(a as (typeof BRAND_SERIES_DOT)[number]));
  });
});

describe("inferChartKind", () => {
  it("detects severity, health, and status series", () => {
    assert.equal(inferChartKind([{ name: "critical" }, { name: "high" }]), "severity");
    assert.equal(inferChartKind([{ name: "healthy" }, { name: "failed" }]), "health");
    assert.equal(inferChartKind([{ name: "open" }, { name: "resolved" }]), "status");
    assert.equal(inferChartKind([{ name: "foo" }, { name: "bar" }]), "generic");
  });
});

describe("formatChartCategory", () => {
  it("capitalizes and replaces underscores", () => {
    assert.equal(formatChartCategory("critical"), "Critical");
    assert.equal(formatChartCategory("never_synced"), "Never Synced");
  });
});

describe("tone map completeness", () => {
  it("every severity/health/status key resolves to a non-empty fill class", () => {
    for (const key of Object.keys(SEVERITY_TONES)) {
      assert.ok(chartFillClassFor(key, "severity").startsWith("fill-"));
    }
    for (const key of Object.keys(HEALTH_TONES)) {
      assert.ok(chartFillClassFor(key, "health").startsWith("fill-"));
    }
    for (const key of Object.keys(STATUS_TONES)) {
      assert.ok(chartFillClassFor(key, "status").startsWith("fill-"));
    }
  });
});
