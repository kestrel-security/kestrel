// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

import { PolicyRowActions } from "@/components/policies/policy-row-actions";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DEFAULT_POLICY_SORT,
  policyFiltersToParams,
  type PolicyFilters,
  type PolicySort,
} from "@/lib/policy-filters";
import type { PolicySummary } from "@/lib/types";

const BASE_PATH = "/policies";

/** `title` is the only ascending sort; the rest put the interesting rows on top. */
const ASCENDING_SORTS = new Set<PolicySort>(["title"]);

/**
 * Where a policy came from, shown under the app name.
 *
 * A pack name is the useful answer; `source` only adds information when it is
 * not the "custom" already implied by the App cell.
 */
function provenance(policy: PolicySummary): string | null {
  if (policy.pack_name) return policy.pack_name;
  return policy.source === "custom" ? null : policy.source;
}

/**
 * Column header that links to `?sort=`.
 *
 * Clicking an inactive column sorts by it; clicking the active one falls back to
 * the default order. The default column has nothing to toggle back to, so it
 * renders as plain text with its direction marker.
 */
function SortHead({
  label,
  sortKey,
  filters,
  className,
}: {
  label: string;
  sortKey: PolicySort;
  filters: PolicyFilters;
  className?: string;
}) {
  const active = filters.sort === sortKey;
  const Marker = ASCENDING_SORTS.has(sortKey) ? ArrowUp : ArrowDown;
  const ariaSort = active
    ? ASCENDING_SORTS.has(sortKey)
      ? "ascending"
      : "descending"
    : "none";

  if (active && sortKey === DEFAULT_POLICY_SORT) {
    return (
      <TableHead aria-sort={ariaSort} className={className}>
        <span className="inline-flex items-center gap-1 text-foreground">
          {label}
          <Marker className="size-3" aria-hidden />
        </span>
      </TableHead>
    );
  }

  const params = policyFiltersToParams({
    ...filters,
    sort: active ? DEFAULT_POLICY_SORT : sortKey,
  });
  const qs = params.toString();

  return (
    <TableHead aria-sort={ariaSort} className={className}>
      <Link
        href={qs ? `${BASE_PATH}?${qs}` : BASE_PATH}
        className="group inline-flex items-center gap-1 transition-colors hover:text-foreground"
      >
        <span className={active ? "text-foreground" : undefined}>{label}</span>
        {active ? (
          <Marker className="size-3" aria-hidden />
        ) : (
          <ChevronsUpDown className="size-3 opacity-0 transition-opacity group-hover:opacity-60" aria-hidden />
        )}
      </Link>
    </TableHead>
  );
}

/**
 * Policies list table. Server Component — sorting is a URL, not client state.
 *
 * `policies` must already be filtered and sorted; this only renders.
 */
export function PolicyListTable({
  policies,
  filters,
  appLabel,
}: {
  policies: PolicySummary[];
  filters: PolicyFilters;
  appLabel: (app: string | null | undefined) => string;
}) {
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="bg-card hover:bg-card">
              <SortHead label="Policy" sortKey="title" filters={filters} />
              <TableHead>App</TableHead>
              <SortHead label="Severity" sortKey="severity" filters={filters} />
              <SortHead label="Open" sortKey="open_desc" filters={filters} />
              <SortHead label="Last run" sortKey="last_run" filters={filters} />
              <TableHead>Status</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {policies.map((p) => (
              <TableRow key={p.id}>
                <TableCell>
                  <Link href={`/policies/${p.id}`} className="font-medium hover:underline">
                    {p.title}
                  </Link>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                    <span className="font-mono text-xs text-muted-foreground" title={p.slug}>
                      {p.slug}
                    </span>
                    {p.resource_type ? (
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px] text-muted-foreground">
                        {p.resource_type}
                      </code>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell>
                  {/* Custom policies always have a null application — the field is derived
                      from the pack→app map — so say "Custom" rather than showing an
                      em-dash that reads as missing data. */}
                  {p.application ? (
                    <span>{appLabel(p.application)}</span>
                  ) : (
                    <span className="text-muted-foreground">Custom</span>
                  )}
                  {/* Provenance sits with the app: which pack shipped this policy. */}
                  {provenance(p) ? (
                    <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                      {provenance(p)}
                    </div>
                  ) : null}
                </TableCell>
                <TableCell>{p.severity ? <SeverityBadge severity={p.severity} /> : "—"}</TableCell>
                <TableCell>
                  {(p.open_finding_count ?? 0) > 0 ? (
                    <Link
                      href={`/findings?policy_slug=${encodeURIComponent(p.slug)}`}
                      className="font-medium tabular-nums text-primary hover:underline"
                    >
                      {p.open_finding_count}
                    </Link>
                  ) : (
                    <span className="tabular-nums text-muted-foreground">0</span>
                  )}
                </TableCell>
                <TableCell>
                  {p.last_evaluation_status ? (
                    <StatusBadge status={p.last_evaluation_status} />
                  ) : (
                    <span className="text-xs text-muted-foreground">never run</span>
                  )}
                  {p.last_evaluated_at ? (
                    <div className="mt-0.5 text-xs tabular-nums text-muted-foreground">
                      <LocalTime value={p.last_evaluated_at} format="relative" />
                    </div>
                  ) : null}
                </TableCell>
                <TableCell>
                  {p.is_enabled === true && <StatusBadge status="enabled" />}
                  {p.is_enabled === false && <StatusBadge status="disabled" />}
                  {p.is_enabled == null && "—"}
                </TableCell>
                <TableCell className="text-right">
                  <PolicyRowActions
                    policyId={p.id}
                    title={p.title}
                    source={p.source}
                    packName={p.pack_name}
                    isEnabled={p.is_enabled}
                    openFindingCount={p.open_finding_count}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}
