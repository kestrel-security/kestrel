// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  drawerBadges,
  fixtureRowCount,
  isStale,
  parseFixtures,
  runSlice,
} from "./policy-editor-state.ts";

describe("isStale", () => {
  it("is never stale for a missing slice", () => {
    expect(isStale(null, "src")).toBe(false);
  });

  it("flips when source drifts", () => {
    const slice = runSlice({ valid: true }, "def policy(r): return True");
    expect(isStale(slice, "def policy(r): return True")).toBe(false);
    expect(isStale(slice, "def policy(r): return False")).toBe(true);
  });

  it("ignores fixture drift for runs that did not consume fixtures", () => {
    const validate = runSlice({ valid: true }, "src");
    expect(isStale(validate, "src", "{}")).toBe(false, "validate does not read fixtures");
  });

  it("flips on fixture drift only for runs that consumed fixtures", () => {
    const test = runSlice({ passed: true }, "src", '{"rows":[]}');
    expect(isStale(test, "src", '{"rows":[]}')).toBe(false);
    expect(isStale(test, "src", '{"rows":[1]}')).toBe(true);
    expect(isStale(test, "other", '{"rows":[]}')).toBe(true, "source still counts");
  });
});

describe("parseFixtures", () => {
  it("accepts a well-formed envelope", () => {
    const parsed = parseFixtures('{"rows": [{"_subject_id": "a"}], "expected_match_subject_ids": ["a"]}');
    expect(parsed.ok).toBe(true);
    expect(fixtureRowCount(parsed)).toBe(1);
  });

  it("rejects empty input with guidance", () => {
    const parsed = parseFixtures("   ");
    expect(parsed.ok).toBe(false);
    expect(parsed.ok === false ? parsed.message : "").toMatch(/empty/i);
  });

  it("rejects non-objects and objects without rows", () => {
    expect(parseFixtures("[]").ok).toBe(false);
    expect(parseFixtures("null").ok).toBe(false);
    const noRows = parseFixtures('{"expected_match_subject_ids": []}');
    expect(noRows.ok).toBe(false);
    expect(noRows.ok === false ? noRows.message : "").toMatch(/rows/);
  });

  it("locates a syntax error so it can become an editor marker", () => {
    const parsed = parseFixtures('{\n  "rows": [],\n}');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.line !== undefined).toBeTruthy();
    expect(parsed.line >= 1).toBeTruthy();
    expect((parsed.column ?? 0) >= 1).toBeTruthy();
  });

  it("returns null row count when unparseable", () => {
    expect(fixtureRowCount(parseFixtures("{oops"))).toBe(null);
  });
});

describe("drawerBadges", () => {
  it("reports fixture rows when valid and an error tone when not", () => {
    const good = drawerBadges({
      fixtures: parseFixtures('{"rows":[{},{}]}'),
      problems: null,
      test: null,
      dryRun: null,
    });
    expect(good.fixtures).toEqual({ count: 2 });

    const bad = drawerBadges({
      fixtures: parseFixtures("{"),
      problems: null,
      test: null,
      dryRun: null,
    });
    expect(bad.fixtures).toEqual({ tone: "error" });
  });

  it("carries problem count, test outcome, and match count", () => {
    const badges = drawerBadges({
      fixtures: parseFixtures('{"rows":[]}'),
      problems: { valid: false, errorCount: 3 },
      test: { passed: false },
      dryRun: { matchCount: 7 },
    });
    expect(badges.problems).toEqual({ tone: "error", count: 3 });
    expect(badges.test).toEqual({ tone: "warning" });
    expect(badges.dryrun).toEqual({ count: 7 });
  });

  it("leaves un-run panels blank rather than showing a zero", () => {
    const badges = drawerBadges({
      fixtures: parseFixtures('{"rows":[]}'),
      problems: null,
      test: null,
      dryRun: null,
    });
    expect(badges.problems).toEqual({});
    expect(badges.test).toEqual({});
    expect(badges.dryrun).toEqual({});
  });
});
