// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { Download } from "lucide-react";

import { FindingsBulkTable } from "@/components/findings/findings-bulk-table";
import { FindingsSearchBar } from "@/components/findings/findings-search-bar";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { apiStatePage } from "@/components/api-state";
import { api } from "@/lib/api";
import { LIST_PAGE_SIZE } from "@/lib/list-filters";
import type {
  FindingFilterPresets,
  FindingOwnershipQueues,
  FindingSummary,
  Operator,
  Page,
  PolicySummary,
} from "@/lib/types";

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<{
    severity?: string;
    status?: string;
    search?: string;
    policy_slug?: string;
    assigned_to_operator_id?: string;
    unassigned?: string;
    open_older_than_days?: string;
    subject_id?: string;
    subject_type?: string;
    application_instance_id?: string;
  }>;
}) {
  const {
    severity,
    status,
    search,
    policy_slug,
    assigned_to_operator_id,
    unassigned: unassignedRaw,
    open_older_than_days,
    subject_id,
    subject_type,
    application_instance_id,
  } = await searchParams;
  const unassigned = unassignedRaw === "true" || unassignedRaw === "1";
  const query = new URLSearchParams();
  if (severity) query.set("severity", severity);
  if (status) query.set("status", status);
  if (search) query.set("search", search);
  if (policy_slug) query.set("policy_slug", policy_slug);
  if (unassigned) query.set("unassigned", "true");
  else if (assigned_to_operator_id) query.set("assigned_to_operator_id", assigned_to_operator_id);
  if (open_older_than_days) query.set("open_older_than_days", open_older_than_days);
  if (subject_id) query.set("subject_id", subject_id);
  if (subject_type) query.set("subject_type", subject_type);
  if (application_instance_id) query.set("application_instance_id", application_instance_id);
  query.set("limit", String(LIST_PAGE_SIZE));

  const hasFilters = Boolean(
    severity ||
      status ||
      search ||
      policy_slug ||
      assigned_to_operator_id ||
      unassigned ||
      open_older_than_days ||
      subject_id ||
      subject_type ||
      application_instance_id,
  );
  const filters = {
    severity,
    status,
    search,
    policy_slug,
    assigned_to_operator_id: unassigned ? undefined : assigned_to_operator_id,
    unassigned: unassigned ? "true" : undefined,
    open_older_than_days,
    subject_id,
    subject_type,
    application_instance_id,
  };

  let findingsPage: Page<FindingSummary> = { items: [], next_cursor: null };
  let operators: Operator[] = [];
  let policies: PolicySummary[] = [];
  let me: Operator | null = null;
  let queues: FindingOwnershipQueues | null = null;
  let presets: FindingFilterPresets = { favorites: [], recent: [] };
  try {
    const [page, ops, pols, meResp, queueResp, presetResp] = await Promise.all([
      api.get<Page<FindingSummary>>(`/findings?${query.toString()}`),
      api.get<Operator[]>("/operators"),
      api.get<PolicySummary[]>("/policies"),
      api.get<Operator>("/auth/me"),
      api.get<FindingOwnershipQueues>("/findings/queues"),
      api.get<FindingFilterPresets>("/findings/presets"),
    ]);
    findingsPage = page;
    operators = ops.filter((o) => o.is_active);
    policies = pols;
    me = meResp;
    queues = queueResp;
    presets = presetResp;
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const current = new URLSearchParams();
  if (severity) current.set("severity", severity);
  if (status) current.set("status", status);
  if (search) current.set("search", search);
  if (policy_slug) current.set("policy_slug", policy_slug);
  if (unassigned) current.set("unassigned", "true");
  else if (assigned_to_operator_id) current.set("assigned_to_operator_id", assigned_to_operator_id);
  if (open_older_than_days) current.set("open_older_than_days", open_older_than_days);
  if (subject_id) current.set("subject_id", subject_id);
  if (subject_type) current.set("subject_type", subject_type);
  if (application_instance_id) current.set("application_instance_id", application_instance_id);

  const listKey = query.toString();
  const exportQuery = current.toString();
  const exportCsvHref = `/api/findings/export?format=csv${exportQuery ? `&${exportQuery}` : ""}`;
  const exportJsonHref = `/api/findings/export?format=json${exportQuery ? `&${exportQuery}` : ""}`;

  // Prefer policies that already have findings on this page, then the rest — keeps Add filter useful.
  const findingSlugs = new Set(
    findingsPage.items.map((f) => f.policy_slug).filter(Boolean) as string[],
  );
  const policyOptions = [
    ...policies.filter((p) => findingSlugs.has(p.slug)),
    ...policies.filter((p) => !findingSlugs.has(p.slug)),
  ];

  return (
    <div>
      <PageHeader
        title="Findings"
        description="Policy violations with evidence, ownership queues, and remediation guidance."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <a href={exportCsvHref}>
                <Download aria-hidden />
                Export CSV
              </a>
            </Button>
            <Button asChild variant="outline" size="sm">
              <a href={exportJsonHref}>
                <Download aria-hidden />
                Export JSON
              </a>
            </Button>
          </>
        }
      />

      <FindingsSearchBar
        filters={filters}
        meOperatorId={me?.id ?? null}
        operators={operators}
        policies={policyOptions}
        queues={
          queues
            ? {
                open_total: queues.open_total,
                open_unassigned: queues.open_unassigned,
                open_assigned_to_me: queues.open_assigned_to_me,
              }
            : null
        }
        favorites={presets.favorites}
        recent={presets.recent}
      />

      {(subject_id || application_instance_id) && (
        <p className="mb-4 rounded-md border border-border bg-muted/40 px-3 py-1.5 text-sm text-muted-foreground">
          Scoped
          {subject_type ? ` to ${subject_type}` : ""}
          {subject_id ? ` ${subject_id.slice(0, 8)}…` : ""}
          {application_instance_id ? ` · app ${application_instance_id.slice(0, 8)}…` : ""}
          {" · "}
          <Link href="/findings" className="text-primary underline">
            clear scope
          </Link>
        </p>
      )}

      {findingsPage.items.length === 0 ? (
        <EmptyState
          title={hasFilters ? "No findings match these filters" : "No findings yet"}
          hint={
            hasFilters
              ? "Try clearing search chips or rewriting the query."
              : "Findings appear once a policy evaluates against collected data."
          }
          action={
            hasFilters ? (
              <Button asChild variant="outline" size="sm">
                <Link href="/findings">Clear filters</Link>
              </Button>
            ) : (
              <Button asChild size="sm">
                <Link href="/policies">Browse policies</Link>
              </Button>
            )
          }
        />
      ) : (
        <FindingsBulkTable
          key={listKey}
          initialFindings={findingsPage.items}
          initialCursor={findingsPage.next_cursor}
          filters={filters}
          pageSize={LIST_PAGE_SIZE}
          operators={operators}
        />
      )}
    </div>
  );
}
