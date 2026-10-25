// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Pure state helpers for the policy editor's results drawer.
 *
 * The drawer keeps Validate / Test / Dry-run results side by side instead of
 * clearing each other, which means a result can outlive the source it was
 * computed from. Rather than deleting results on every keystroke, we snapshot
 * the inputs each run was based on and mark the panel *stale* — losing a
 * dry-run's match list because a comment was edited is worse than showing it
 * with a caveat.
 */

export const DRAWER_TABS = ["fixtures", "problems", "test", "dryrun"] as const;
export type DrawerTab = (typeof DRAWER_TABS)[number];

export const DRAWER_TAB_LABELS: Record<DrawerTab, string> = {
  fixtures: "Fixtures",
  problems: "Problems",
  test: "Test",
  dryrun: "Dry-run",
};

/** A run result plus the inputs it was computed from. */
export type RunSlice<T> = {
  data: T;
  sourceSnapshot: string;
  /** Only set for runs that consume fixtures (the fixture test). */
  fixturesSnapshot?: string;
};

export function runSlice<T>(data: T, source: string, fixtures?: string): RunSlice<T> {
  return fixtures === undefined
    ? { data, sourceSnapshot: source }
    : { data, sourceSnapshot: source, fixturesSnapshot: fixtures };
}

/**
 * True when the current editor content has drifted from what this run used.
 * Fixtures only count when the run actually consumed them.
 */
export function isStale(
  slice: RunSlice<unknown> | null,
  source: string,
  fixtures?: string,
): boolean {
  if (!slice) return false;
  if (slice.sourceSnapshot !== source) return true;
  if (slice.fixturesSnapshot === undefined) return false;
  return fixtures !== undefined && slice.fixturesSnapshot !== fixtures;
}

export type FixturesValue = {
  rows?: unknown[];
  expected_match_subject_ids?: unknown[];
};

export type FixturesParse =
  | { ok: true; value: FixturesValue }
  | { ok: false; message: string; line?: number; column?: number };

/**
 * Parse the fixtures editor content, recovering a line/column from the engine's
 * error message where possible so it can become a Monaco marker.
 *
 * Without this, an unbalanced brace only surfaces after a server round-trip as a
 * generic "Fixtures must be valid JSON".
 */
export function parseFixtures(text: string): FixturesParse {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, message: "Fixtures are empty — add rows and expected_match_subject_ids." };
  }
  try {
    const value = JSON.parse(trimmed) as Record<string, unknown>;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, message: "Fixtures must be a JSON object." };
    }
    if (!Array.isArray(value.rows)) {
      return { ok: false, message: 'Fixtures need a "rows" array.' };
    }
    return { ok: true, value: value as FixturesValue };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message, ...locateJsonError(message, text) };
  }
}

/**
 * V8 reports either `at position N` or `at line L column C`. Normalize both to a
 * 1-based line/column; return nothing when neither form is present.
 */
function locateJsonError(message: string, text: string): { line?: number; column?: number } {
  const lineCol = message.match(/at line (\d+) column (\d+)/i);
  if (lineCol) {
    return { line: Number(lineCol[1]), column: Number(lineCol[2]) };
  }
  const position = message.match(/at position (\d+)/i);
  if (!position) return {};
  const offset = Math.min(Number(position[1]), text.length);
  const before = text.slice(0, offset);
  const line = before.split("\n").length;
  const column = offset - (before.lastIndexOf("\n") + 1) + 1;
  return { line, column };
}

/** Row count for the Fixtures tab badge, or null when unparseable. */
export function fixtureRowCount(parsed: FixturesParse): number | null {
  return parsed.ok ? (parsed.value.rows?.length ?? 0) : null;
}

export type DrawerBadge = {
  /** Numeric pill, e.g. problem count or match count. */
  count?: number;
  /** Coloured dot for pass/fail-style state. */
  tone?: "error" | "success" | "warning";
};

/**
 * Per-tab badge descriptors so the drawer strip reports state without the user
 * opening each panel.
 */
export function drawerBadges(state: {
  fixtures: FixturesParse;
  problems: { valid: boolean; errorCount: number } | null;
  test: { passed: boolean } | null;
  dryRun: { matchCount: number } | null;
}): Record<DrawerTab, DrawerBadge> {
  const rows = fixtureRowCount(state.fixtures);
  return {
    fixtures: state.fixtures.ok
      ? { count: rows ?? 0 }
      : { tone: "error" },
    problems: state.problems
      ? state.problems.valid
        ? { tone: "success" }
        : { tone: "error", count: state.problems.errorCount }
      : {},
    test: state.test ? { tone: state.test.passed ? "success" : "warning" } : {},
    dryrun: state.dryRun ? { count: state.dryRun.matchCount } : {},
  };
}
