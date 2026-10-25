// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Before/after presentation for the Changes feed.
 *
 *  Access being granted has no prior value, so rendering it as `— → Admin`
 *  invents a transition that never happened and tints the absent side like a
 *  removal. `change_type` already separates an addition from a real transition,
 *  so the cell shape follows it: `+ Admin`, `− Admin`, or `read → admin`.
 */

import { countOf } from "@/lib/plural";

export type ChangeDelta =
  | { kind: "added"; value: string }
  | { kind: "removed"; value: string }
  | { kind: "modified"; before: string; after: string }
  | { kind: "unrecorded" };

/** Evidence sometimes arrives already stringified as an em dash. */
export function isEmptyChangeValue(value: unknown): boolean {
  return value == null || value === "—";
}

/** Full value for the expanded evidence panel; `null` means "no such side". */
export function formatChangeValue(value: unknown): string | null {
  if (isEmptyChangeValue(value)) return null;
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    if (value.every((item) => typeof item === "string")) return value.join(", ");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Table-width value; collapses collections to a count. */
export function formatCompactChangeValue(value: unknown): string | null {
  if (isEmptyChangeValue(value)) return null;
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    if (value.every((item) => typeof item === "string")) {
      if (value.length <= 2) return value.join(", ");
      return `${value.length} scopes`;
    }
    return countOf(value.length, "item");
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") return "changed";
  return String(value);
}

export function changeDelta(change: {
  change_type: string;
  before: unknown;
  after: unknown;
}): ChangeDelta {
  const before = formatCompactChangeValue(change.before);
  const after = formatCompactChangeValue(change.after);

  // An entity appearing or disappearing stays an addition/removal even when the
  // classifier synthesized prose for the missing side ("Not a member"), which
  // still shows in the expanded panel.
  if (change.change_type === "created") {
    return after === null ? { kind: "unrecorded" } : { kind: "added", value: after };
  }
  if (change.change_type === "deleted") {
    return before === null ? { kind: "unrecorded" } : { kind: "removed", value: before };
  }

  if (before !== null && after !== null) return { kind: "modified", before, after };
  if (after !== null) return { kind: "added", value: after };
  if (before !== null) return { kind: "removed", value: before };
  return { kind: "unrecorded" };
}
