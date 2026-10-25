// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound, unstable_rethrow } from "next/navigation";

import { FilterChip, ListSearchForm } from "@/components/list-filters";
import { AuditLogTable } from "@/components/settings/audit-log-table";
import { SettingsSection } from "@/components/settings/settings-section";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { api } from "@/lib/api";
import { LIST_PAGE_SIZE, filterHref } from "@/lib/list-filters";
import type { AuditLogEntry, Operator, Page } from "@/lib/types";

const COMMON_ACTIONS = [
  "finding.updated",
  "finding.exception_created",
  "auth.login_succeeded",
  "auth.login_failed",
  "operator.created",
  "operator.updated",
  "operator.notification_preferences_updated",
  "connector_instance.created",
  "connector_instance.sync_triggered",
  "policy.created",
  "policy.updated",
  "webhook.created",
  "webhook.delivery_retried",
  "pack.installed",
];

export default async function AuditSettingsPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string }>;
}) {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const { action } = await searchParams;
  const actionFilter = action?.trim() || undefined;

  const query = new URLSearchParams();
  if (actionFilter) query.set("action", actionFilter);
  query.set("limit", String(LIST_PAGE_SIZE));

  let page: Page<AuditLogEntry> = { items: [], next_cursor: null };
  try {
    page = await api.get<Page<AuditLogEntry>>(`/audit-log?${query.toString()}`);
  } catch (error) {
    unstable_rethrow(error);
    page = { items: [], next_cursor: null };
  }

  const current = new URLSearchParams();
  if (actionFilter) current.set("action", actionFilter);

  const exportQuery = current.toString();
  const exportCsvHref = `/api/audit-log/export?format=csv${exportQuery ? `&${exportQuery}` : ""}`;
  const exportJsonHref = `/api/audit-log/export?format=json${exportQuery ? `&${exportQuery}` : ""}`;

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Audit log"
        description="Append-only trail of operator actions in this org. Admin-only — spans every operator's mutations, not just your own."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <a href={exportCsvHref}>Export CSV</a>
            </Button>
            <Button asChild variant="outline" size="sm">
              <a href={exportJsonHref}>Export JSON</a>
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>Filter by exact action name, or pick a common action below.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <ListSearchForm
            action="/settings/audit"
            name="action"
            defaultValue={actionFilter}
            placeholder="Filter by exact action (e.g. finding.updated)…"
            preserve={{}}
          />
          <div className="flex flex-wrap items-center gap-1 text-sm">
            <span className="mr-1 text-muted-foreground">Common:</span>
            {COMMON_ACTIONS.map((a) => (
              <FilterChip
                key={a}
                href={filterHref("/settings/audit", current, "action", a)}
                active={actionFilter === a}
              >
                {a}
              </FilterChip>
            ))}
            {actionFilter ? (
              <Link href="/settings/audit" className="ml-2 text-muted-foreground hover:underline">
                Clear
              </Link>
            ) : null}
          </div>

          {page.items.length === 0 ? (
            <EmptyState
              title={actionFilter ? "No audit events match this action" : "No audit events yet"}
              hint={
                actionFilter
                  ? "Try another action filter, or clear to see the full trail."
                  : "Mutations (login, finding triage, integrations, policies) write rows here."
              }
            />
          ) : (
            <AuditLogTable
              key={query.toString()}
              initialItems={page.items}
              initialCursor={page.next_cursor}
              actionFilter={actionFilter}
              pageSize={LIST_PAGE_SIZE}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
