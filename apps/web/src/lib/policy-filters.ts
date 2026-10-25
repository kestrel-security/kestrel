// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * In-memory filtering, sorting, and facet counting for the Policies list.
 *
 * `GET /policies` takes no query params and returns the full org-scoped array,
 * so all list behaviour lives here. Pure and dependency-free so it can be
 * unit-tested under `node --test`; the page stays a thin Server Component.
 */

import type { PolicySummary } from "@/lib/types";

export const RESOURCE_TYPES = [
  "identity",
  "grant",
  "application",
  "oauth_application",
  "tenant_setting",
  "event",
] as const;

export const FRAMEWORKS = [
  { id: "cis", label: "CIS" },
  { id: "nist_csf", label: "NIST CSF" },
  { id: "soc2", label: "SOC2" },
  { id: "cisa", label: "CISA" },
] as const;

export const POLICY_SORTS = ["open_desc", "severity", "last_run", "title"] as const;
export type PolicySort = (typeof POLICY_SORTS)[number];
export const DEFAULT_POLICY_SORT: PolicySort = "open_desc";

export const PER_PAGE_OPTIONS = [25, 50, 100] as const;
export type PerPage = (typeof PER_PAGE_OPTIONS)[number];
export const DEFAULT_PER_PAGE: PerPage = 25;

export type PolicyFilters = {
  enabled?: "true" | "false";
  source?: "pack" | "custom" | "system";
  resource_type?: string;
  has_open?: "true" | "false";
  application?: string;
  framework?: string;
  /** Pack name, from the marketplace's "View installed" link. */
  pack?: string;
  q?: string;
  sort: PolicySort;
  /** 1-based. Never serialized by `policyFiltersToParams`, so any change of
      filter, sort, or query lands on page 1; only pagination links set it. */
  page: number;
  per: PerPage;
};

/** Facets a chip row can filter on — `sort` and `q` are not facets. */
export type FacetKey =
  | "enabled"
  | "source"
  | "resource_type"
  | "has_open"
  | "application"
  | "framework"
  | "pack";

/** Frameworks per pack name, derived from `GET /packs`. */
export type PackFrameworks = Map<string, Set<string>>;

type RawParams = Record<string, string | string[] | undefined>;

function first(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

export function isPolicySort(raw: unknown): raw is PolicySort {
  return typeof raw === "string" && (POLICY_SORTS as readonly string[]).includes(raw);
}

function isPerPage(raw: number): raw is PerPage {
  return (PER_PAGE_OPTIONS as readonly number[]).includes(raw);
}

/** A positive integer from a query param, else `fallback`. "0", "-1", "1.5", "abc" all fall back. */
function positiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || !/^\d+$/.test(raw)) return fallback;
  const n = Number(raw);
  return n >= 1 ? n : fallback;
}

export function parsePolicyFilters(params: RawParams): PolicyFilters {
  const enabled = first(params.enabled);
  const source = first(params.source);
  const resourceType = first(params.resource_type);
  const hasOpen = first(params.has_open);
  const framework = first(params.framework);
  const sort = first(params.sort);
  const per = positiveInt(first(params.per), DEFAULT_PER_PAGE);

  return {
    enabled: enabled === "true" || enabled === "false" ? enabled : undefined,
    source:
      source === "pack" || source === "custom" || source === "system" ? source : undefined,
    resource_type: (RESOURCE_TYPES as readonly string[]).includes(resourceType ?? "")
      ? resourceType
      : undefined,
    has_open: hasOpen === "true" || hasOpen === "false" ? hasOpen : undefined,
    application: first(params.application),
    framework: FRAMEWORKS.some((f) => f.id === framework) ? framework : undefined,
    pack: first(params.pack),
    q: first(params.q)?.toLowerCase(),
    sort: isPolicySort(sort) ? sort : DEFAULT_POLICY_SORT,
    page: positiveInt(first(params.page), 1),
    per: isPerPage(per) ? per : DEFAULT_PER_PAGE,
  };
}

/** True when anything narrowing is active (drives the "Clear filters" affordance). */
export function hasActiveFilters(filters: PolicyFilters): boolean {
  return Boolean(
    filters.enabled ||
      filters.source ||
      filters.resource_type ||
      filters.has_open ||
      filters.application ||
      filters.framework ||
      filters.pack ||
      filters.q,
  );
}

/**
 * Serialize back to a query string, dropping the default sort and page size.
 *
 * `page` is deliberately left out: every chip, sort header, and the search
 * form build their links from this, so changing any of them returns to the
 * first page. `pageHref` is the one place that adds it.
 */
export function policyFiltersToParams(filters: PolicyFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.enabled) params.set("enabled", filters.enabled);
  if (filters.source) params.set("source", filters.source);
  if (filters.resource_type) params.set("resource_type", filters.resource_type);
  if (filters.has_open) params.set("has_open", filters.has_open);
  if (filters.application) params.set("application", filters.application);
  if (filters.framework) params.set("framework", filters.framework);
  if (filters.pack) params.set("pack", filters.pack);
  if (filters.q) params.set("q", filters.q);
  if (filters.sort !== DEFAULT_POLICY_SORT) params.set("sort", filters.sort);
  if (filters.per !== DEFAULT_PER_PAGE) params.set("per", String(filters.per));
  return params;
}

function withQuery(basePath: string, params: URLSearchParams): string {
  const qs = params.toString();
  return qs ? `${basePath}?${qs}` : basePath;
}

/** Link to one page of the current view. Page 1 is the bare filter URL. */
export function pageHref(basePath: string, filters: PolicyFilters, page: number): string {
  const params = policyFiltersToParams(filters);
  if (page > 1) params.set("page", String(page));
  return withQuery(basePath, params);
}

/** Link that changes the page size; returns to page 1 since the pages no longer line up. */
export function perPageHref(basePath: string, filters: PolicyFilters, per: PerPage): string {
  return withQuery(basePath, policyFiltersToParams({ ...filters, per }));
}

export type PageSlice<T> = {
  rows: T[];
  /** The page actually shown: a stale `?page=` past the end is clamped to the last page. */
  page: number;
  pageCount: number;
  /** 1-based inclusive bounds of `rows` within the full set; both 0 when empty. */
  start: number;
  end: number;
  total: number;
};

export function paginate<T>(rows: T[], page: number, per: number): PageSlice<T> {
  const total = rows.length;
  const pageCount = Math.max(1, Math.ceil(total / per));
  const current = Math.min(Math.max(1, page), pageCount);
  const offset = (current - 1) * per;
  const slice = rows.slice(offset, offset + per);
  return {
    rows: slice,
    page: current,
    pageCount,
    start: slice.length ? offset + 1 : 0,
    end: offset + slice.length,
    total,
  };
}

function matchesFacet(
  policy: PolicySummary,
  facet: FacetKey,
  filters: PolicyFilters,
  packFrameworks: PackFrameworks,
): boolean {
  switch (facet) {
    case "enabled":
      if (!filters.enabled) return true;
      return policy.is_enabled === (filters.enabled === "true");
    case "source":
      if (!filters.source) return true;
      return policy.source === filters.source;
    case "resource_type":
      if (!filters.resource_type) return true;
      return policy.resource_type === filters.resource_type;
    case "has_open": {
      if (!filters.has_open) return true;
      const open = policy.open_finding_count ?? 0;
      return filters.has_open === "true" ? open > 0 : open === 0;
    }
    case "application":
      if (!filters.application) return true;
      return (policy.application ?? "") === filters.application;
    case "framework": {
      if (!filters.framework) return true;
      // Frameworks come from pack metadata, so custom policies never match one.
      if (!policy.pack_name) return false;
      return packFrameworks.get(policy.pack_name)?.has(filters.framework) ?? false;
    }
    case "pack":
      if (!filters.pack) return true;
      return policy.pack_name === filters.pack;
  }
}

const ALL_FACETS: FacetKey[] = [
  "enabled",
  "source",
  "resource_type",
  "has_open",
  "application",
  "framework",
  "pack",
];

/**
 * Free-text search. Every whitespace-separated token must match somewhere in
 * the title, slug (whole or split on `-`, `_`, `.`), pack name, application,
 * severity, or resource type, so "okta mfa" finds every Okta MFA policy in
 * either word order and "github-posture" finds a pack's policies.
 */
function matchesQuery(policy: PolicySummary, q: string | undefined): boolean {
  if (!q) return true;
  const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const slug = policy.slug.toLowerCase();
  const haystack = [
    policy.title.toLowerCase(),
    slug,
    ...slug.split(/[-_.]/),
    policy.pack_name?.toLowerCase() ?? "",
    policy.application?.toLowerCase() ?? "",
    policy.severity?.toLowerCase() ?? "",
    policy.resource_type?.toLowerCase() ?? "",
  ].filter(Boolean);
  return tokens.every((token) => haystack.some((field) => field.includes(token)));
}

/**
 * Apply filters, optionally ignoring one facet.
 *
 * `except` is what makes chip counts honest: a chip's count is the size of the
 * set narrowed by every *other* active facet, so it predicts what clicking it
 * would actually yield rather than counting the whole corpus.
 */
export function applyPolicyFilters(
  policies: PolicySummary[],
  filters: PolicyFilters,
  packFrameworks: PackFrameworks,
  options: { except?: FacetKey } = {},
): PolicySummary[] {
  return policies.filter((policy) => {
    if (!matchesQuery(policy, filters.q)) return false;
    return ALL_FACETS.every(
      (facet) =>
        facet === options.except || matchesFacet(policy, facet, filters, packFrameworks),
    );
  });
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Stable sort — ties fall back to title so ordering never jitters between renders. */
export function sortPolicies(policies: PolicySummary[], sort: PolicySort): PolicySummary[] {
  const byTitle = (a: PolicySummary, b: PolicySummary) =>
    a.title.localeCompare(b.title) || a.slug.localeCompare(b.slug);

  const sorted = [...policies];
  switch (sort) {
    case "open_desc":
      return sorted.sort(
        (a, b) => (b.open_finding_count ?? 0) - (a.open_finding_count ?? 0) || byTitle(a, b),
      );
    case "severity":
      return sorted.sort(
        (a, b) =>
          (SEVERITY_RANK[b.severity ?? ""] ?? 0) - (SEVERITY_RANK[a.severity ?? ""] ?? 0) ||
          byTitle(a, b),
      );
    case "last_run":
      return sorted.sort((a, b) => {
        // Never-run policies sort last: no timestamp is not "oldest".
        const at = a.last_evaluated_at ? Date.parse(a.last_evaluated_at) : Number.NEGATIVE_INFINITY;
        const bt = b.last_evaluated_at ? Date.parse(b.last_evaluated_at) : Number.NEGATIVE_INFINITY;
        return bt - at || byTitle(a, b);
      });
    case "title":
      return sorted.sort(byTitle);
  }
}

export type FacetCount = { value: string; count: number };

/**
 * Counts for one facet's chips, each narrowed by the *other* active facets.
 * `values` is the candidate list; pass the same order you render chips in.
 */
export function facetCounts(
  policies: PolicySummary[],
  filters: PolicyFilters,
  packFrameworks: PackFrameworks,
  facet: FacetKey,
  values: readonly string[],
): FacetCount[] {
  const base = applyPolicyFilters(policies, filters, packFrameworks, { except: facet });
  return values.map((value) => ({
    value,
    count: base.filter((policy) =>
      matchesFacet(policy, facet, { ...filters, [facet]: value } as PolicyFilters, packFrameworks),
    ).length,
  }));
}

/** Distinct applications present across the corpus, for the App chip row. */
export function applicationsPresent(policies: PolicySummary[]): string[] {
  return [...new Set(policies.map((p) => p.application).filter(Boolean) as string[])].sort();
}
