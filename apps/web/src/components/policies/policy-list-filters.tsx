// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import type { ReactNode } from "react";

import { ListSearchForm } from "@/components/list-filters";
import { FilterChip } from "@/components/ui/filter-chip";
import { filterHref } from "@/lib/list-filters";
import {
  FRAMEWORKS,
  applicationsPresent,
  applyPolicyFilters,
  facetCounts,
  hasActiveFilters,
  policyFiltersToParams,
  type FacetKey,
  type PackFrameworks,
  type PolicyFilters,
} from "@/lib/policy-filters";
import type { PolicySummary } from "@/lib/types";

const BASE_PATH = "/policies";

/** Chips are rendered only for sources actually present in the corpus. */
const SOURCES = [
  { id: "pack", label: "Pack" },
  { id: "custom", label: "Custom" },
  { id: "system", label: "System" },
] as const;

/** App + Framework collapse behind "More filters" past this many value chips. */
const ADVANCED_CHIP_BUDGET = 6;

function href(current: URLSearchParams, mutate: (next: URLSearchParams) => void): string {
  const next = new URLSearchParams(current);
  mutate(next);
  const qs = next.toString();
  return qs ? `${BASE_PATH}?${qs}` : BASE_PATH;
}

function countMap(
  policies: PolicySummary[],
  filters: PolicyFilters,
  packFrameworks: PackFrameworks,
  facet: FacetKey,
  values: readonly string[],
): Map<string, number> {
  return new Map(
    facetCounts(policies, filters, packFrameworks, facet, values).map((c) => [c.value, c.count]),
  );
}

function FacetRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-eyebrow w-20 shrink-0">{label}</span>
      {children}
    </div>
  );
}

/**
 * Toolbar for the Policies list: search, grouped filter chips, result count.
 *
 * Server Component — `FilterChip` renders as a `Link` when given `href`, so the
 * whole row stays server-rendered and every filter is a shareable URL.
 *
 * Counts come from `facetCounts`, which narrows each chip by the *other* active
 * facets: the number on a chip is what clicking it will actually yield.
 */
export function PolicyListFilters({
  policies,
  filters,
  packFrameworks,
  shown,
  appLabel,
  rawQuery,
}: {
  /** Full org corpus — chip counts are computed against this, not the filtered view. */
  policies: PolicySummary[];
  filters: PolicyFilters;
  packFrameworks: PackFrameworks;
  /** Rows currently displayed, for the "N of M shown" line. */
  shown: number;
  appLabel: (app: string | null | undefined) => string;
  /** Un-normalized `q` so the search box echoes what was typed, not the lowercased form. */
  rawQuery?: string;
}) {
  const current = policyFiltersToParams(filters);
  const preserve = Object.fromEntries(
    [...current.entries()].filter(([key]) => key !== "q"),
  ) as Record<string, string>;

  // Size of the set narrowed by every facet *except* this one — the "All …" chip.
  const anyCount = (facet: FacetKey) =>
    applyPolicyFilters(policies, filters, packFrameworks, { except: facet }).length;

  const enabledCounts = countMap(policies, filters, packFrameworks, "enabled", ["true", "false"]);
  const sourcesPresent = SOURCES.filter(
    (s) => filters.source === s.id || policies.some((p) => p.source === s.id),
  );
  const sourceCounts = countMap(
    policies,
    filters,
    packFrameworks,
    "source",
    sourcesPresent.map((s) => s.id),
  );
  const openCounts = countMap(policies, filters, packFrameworks, "has_open", ["true", "false"]);

  const apps = applicationsPresent(policies);
  const appCounts = countMap(policies, filters, packFrameworks, "application", apps);
  const frameworkCounts = countMap(
    policies,
    filters,
    packFrameworks,
    "framework",
    FRAMEWORKS.map((f) => f.id),
  );

  const advancedActive = Boolean(filters.application || filters.framework);
  const collapseAdvanced = apps.length + FRAMEWORKS.length > ADVANCED_CHIP_BUDGET;

  const advanced = (
    <>
      {apps.length > 0 ? (
        <FacetRow label="App">
          <FilterChip
            href={href(current, (p) => p.delete("application"))}
            label="All apps"
            active={!filters.application}
            count={anyCount("application")}
          />
          {apps.map((app) => (
            <FilterChip
              key={app}
              href={filterHref(BASE_PATH, current, "application", app)}
              label={appLabel(app)}
              active={filters.application === app}
              count={appCounts.get(app) ?? 0}
            />
          ))}
        </FacetRow>
      ) : null}
      <FacetRow label="Framework">
        <FilterChip
          href={href(current, (p) => p.delete("framework"))}
          label="All frameworks"
          active={!filters.framework}
          count={anyCount("framework")}
        />
        {FRAMEWORKS.map((fw) => (
          <FilterChip
            key={fw.id}
            href={filterHref(BASE_PATH, current, "framework", fw.id)}
            label={fw.label}
            active={filters.framework === fw.id}
            count={frameworkCounts.get(fw.id) ?? 0}
          />
        ))}
      </FacetRow>
    </>
  );

  return (
    <div className="mb-4 space-y-3">
      <h2 className="text-lg font-medium">Installed policies</h2>
      {/* Search leads: it is the fastest way through a few hundred policies,
          so it sits above the chips rather than beside the heading. */}
      <ListSearchForm
        action={BASE_PATH}
        name="q"
        defaultValue={rawQuery}
        placeholder="Search by name, slug, pack, severity, or type…"
        preserve={preserve}
      />

      <div className="space-y-2">
        <FacetRow label="Status">
          <FilterChip
            href={href(current, (p) => p.delete("enabled"))}
            label="All"
            active={!filters.enabled}
            count={anyCount("enabled")}
          />
          <FilterChip
            href={filterHref(BASE_PATH, current, "enabled", "true")}
            label="Enabled"
            active={filters.enabled === "true"}
            count={enabledCounts.get("true") ?? 0}
          />
          <FilterChip
            href={filterHref(BASE_PATH, current, "enabled", "false")}
            label="Disabled"
            active={filters.enabled === "false"}
            count={enabledCounts.get("false") ?? 0}
          />
        </FacetRow>

        {sourcesPresent.length > 1 ? (
          <FacetRow label="Source">
            <FilterChip
              href={href(current, (p) => p.delete("source"))}
              label="All"
              active={!filters.source}
              count={anyCount("source")}
            />
            {sourcesPresent.map((s) => (
              <FilterChip
                key={s.id}
                href={filterHref(BASE_PATH, current, "source", s.id)}
                label={s.label}
                active={filters.source === s.id}
                count={sourceCounts.get(s.id) ?? 0}
              />
            ))}
          </FacetRow>
        ) : null}

        <FacetRow label="Findings">
          <FilterChip
            href={href(current, (p) => p.delete("has_open"))}
            label="Any"
            active={!filters.has_open}
            count={anyCount("has_open")}
          />
          <FilterChip
            href={filterHref(BASE_PATH, current, "has_open", "true")}
            label="Has open"
            active={filters.has_open === "true"}
            count={openCounts.get("true") ?? 0}
          />
          <FilterChip
            href={filterHref(BASE_PATH, current, "has_open", "false")}
            label="Clean"
            active={filters.has_open === "false"}
            count={openCounts.get("false") ?? 0}
          />
        </FacetRow>

        {/* `resource_type` has no chip row of its own (it lives in the Policy cell),
            so surface it here when a link or bookmark set it — otherwise the list
            is narrowed with nothing on screen explaining why. */}
        {filters.resource_type ? (
          <FacetRow label="Type">
            <FilterChip
              href={href(current, (p) => p.delete("resource_type"))}
              label={filters.resource_type}
              active
              count={applyPolicyFilters(policies, filters, packFrameworks).length}
            />
          </FacetRow>
        ) : null}

        {/* Set by the pack marketplace's "View installed" link; no chip row of its own. */}
        {filters.pack ? (
          <FacetRow label="Pack">
            <FilterChip
              href={href(current, (p) => p.delete("pack"))}
              label={filters.pack}
              active
              count={applyPolicyFilters(policies, filters, packFrameworks).length}
            />
          </FacetRow>
        ) : null}

        {collapseAdvanced ? (
          <details open={advancedActive}>
            <summary className="cursor-pointer text-xs text-muted-foreground transition-colors hover:text-foreground">
              More filters
            </summary>
            <div className="mt-2 space-y-2">{advanced}</div>
          </details>
        ) : (
          advanced
        )}
      </div>

      <p className="text-sm text-muted-foreground">
        {shown} of {policies.length} shown
        {hasActiveFilters(filters) ? (
          <>
            {" · "}
            <Link href={BASE_PATH} className="transition-colors hover:text-foreground hover:underline">
              Clear filters
            </Link>
          </>
        ) : null}
      </p>
    </div>
  );
}
