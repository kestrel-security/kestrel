// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Guards for dynamic route segments that a proxy route interpolates into an
 * upstream API URL. A segment that is not exactly the expected shape must
 * never reach the URL: "../" in an id would retarget the request. */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

// Pack names (`packs/<name>/pack.yaml`): lowercase words joined by hyphens or
// underscores. No dots or slashes, so a name can never be "." or "..".
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,99}$/i;

export function isSlug(value: string): boolean {
  return SLUG_RE.test(value);
}

/** Formats `POST /dashboards/{id}/export` accepts. */
export const DASHBOARD_EXPORT_FORMATS = ["pdf", "csv", "json", "html"] as const;

export type DashboardExportFormat = (typeof DASHBOARD_EXPORT_FORMATS)[number];

export function dashboardExportFormat(value: string | null): DashboardExportFormat | null {
  const format = value || "pdf";
  return (DASHBOARD_EXPORT_FORMATS as readonly string[]).includes(format)
    ? (format as DashboardExportFormat)
    : null;
}
