// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * URL-driven tabs for the policy detail workspace (`/policies/{id}?tab=`).
 *
 * Tabs are navigations, not local state, so the detail page stays a Server
 * Component and each tab fetches only its own data. Kept pure and dependency-free
 * so it can be unit-tested under `node --test`.
 */

export const POLICY_TABS = ["overview", "code", "findings", "evaluations", "versions"] as const;

export type PolicyTab = (typeof POLICY_TABS)[number];

export const DEFAULT_POLICY_TAB: PolicyTab = "overview";

/** Short labels for the tab strip. */
export const POLICY_TAB_LABELS: Record<PolicyTab, string> = {
  overview: "Overview",
  code: "Code & test",
  findings: "Findings",
  evaluations: "Evaluations",
  versions: "Versions",
};

/**
 * One-shot params written by server-action redirects (success/forbidden banners).
 * Dropped when building tab links so a banner doesn't survive a tab click.
 */
const TRANSIENT_PARAMS = ["error", "evaluated", "matches", "status"] as const;

export function isPolicyTab(raw: unknown): raw is PolicyTab {
  return typeof raw === "string" && (POLICY_TABS as readonly string[]).includes(raw);
}

/** Unknown, absent, or malformed `?tab=` falls back to Overview rather than 404ing. */
export function parsePolicyTab(raw: string | string[] | undefined): PolicyTab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return isPolicyTab(value) ? value : DEFAULT_POLICY_TAB;
}

/**
 * Link target for a tab. Overview is the canonical bare path (no `?tab=overview`)
 * so the detail URL stays clean.
 */
export function policyTabHref(
  policyId: string,
  tab: PolicyTab,
  current?: URLSearchParams,
): string {
  const params = new URLSearchParams(current ?? undefined);
  for (const key of TRANSIENT_PARAMS) params.delete(key);
  params.delete("tab");
  if (tab !== DEFAULT_POLICY_TAB) params.set("tab", tab);
  const qs = params.toString();
  return qs ? `/policies/${policyId}?${qs}` : `/policies/${policyId}`;
}

/**
 * Tab link with extra one-shot params appended — used by server actions that
 * redirect back to the page carrying a result banner.
 */
export function policyTabHrefWith(
  policyId: string,
  tab: PolicyTab,
  extra: Record<string, string | number>,
): string {
  const params = new URLSearchParams();
  if (tab !== DEFAULT_POLICY_TAB) params.set("tab", tab);
  for (const [key, value] of Object.entries(extra)) params.set(key, String(value));
  const qs = params.toString();
  return qs ? `/policies/${policyId}?${qs}` : `/policies/${policyId}`;
}
