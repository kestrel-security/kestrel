// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Which connector config fields the create form must have a value for.
 *
 * Manifests list `optional_config_fields` (a subset of `config_fields`) for
 * values that only apply to some setups, e.g. Slack's `enterprise_id`, which
 * only an Enterprise Grid org-level token has.
 */
export function isOptionalConfigField(field: string, optional: readonly string[] | null | undefined): boolean {
  return (optional ?? []).includes(field);
}

/** The first required field left blank, or null when every one has a value. */
export function firstMissingConfigField(
  fields: readonly string[],
  optional: readonly string[] | null | undefined,
  values: Record<string, string | undefined>,
): string | null {
  for (const field of fields) {
    if (isOptionalConfigField(field, optional)) continue;
    if (!(values[field] ?? "").trim()) return field;
  }
  return null;
}
