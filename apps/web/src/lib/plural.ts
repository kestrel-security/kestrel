// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * The form of `singular` to use beside `count`: `plural(1, "hop")` is "hop",
 * `plural(3, "hop")` is "hops". Pass the plural form when it isn't just
 * `singular + "s"` (`plural(n, "delivery", "deliveries")`). Only exactly one
 * is singular, so zero reads "0 hops".
 */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return count === 1 ? singular : pluralForm;
}

/** `count` followed by the matching form: `countOf(2, "match", "matches")` is "2 matches". */
export function countOf(count: number, singular: string, pluralForm?: string): string {
  return `${count} ${plural(count, singular, pluralForm)}`;
}
