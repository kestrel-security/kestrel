// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { AlertTriangle } from "lucide-react";
import Link from "next/link";

import { ChangeRow } from "@/components/changes/change-row";
import { ChangesSearchBar } from "@/components/changes/changes-search-bar";
import { apiStatePage } from "@/components/api-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { LocalTime } from "@/components/ui/local-time";
import { PageHeader } from "@/components/ui/page-header";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ApiError, api } from "@/lib/api";
import {
  changesFiltersFromParams,
  changesFiltersToParams,
  changesFiltersToSearchParam,
} from "@/lib/changes-search";
import type { ChangeFeed, ConnectorInstanceSummary } from "@/lib/types";

const DEFAULT_WINDOW = "168";

export default async function ChangesPage({
  searchParams,
}: {
  searchParams: Promise<{
    window_hours?: string;
    change_class?: string;
    min_significance?: string;
    search?: string;
    connector_instance_id?: string;
  }>;
}) {
  const params = await searchParams;
  const filters = changesFiltersFromParams({
    ...params,
    window_hours: params.window_hours || DEFAULT_WINDOW,
  });

  const query = changesFiltersToParams(filters);
  query.set("window_hours", filters.window_hours || DEFAULT_WINDOW);
  query.set("min_significance", filters.min_significance || "medium");
  const searchParam = changesFiltersToSearchParam(filters);
  if (searchParam) {
    query.set("search", searchParam);
  }
  // change_class also as dedicated param when set via chips / Add filter
  if (filters.change_class) {
    query.set("change_class", filters.change_class);
  }
  if (filters.connector_instance_id) {
    query.set("connector_instance_id", filters.connector_instance_id);
  }

  let feed: ChangeFeed;
  let connectors: ConnectorInstanceSummary[] = [];
  try {
    const [feedResp, connectorResp] = await Promise.all([
      api.get<ChangeFeed>(`/changes?${query.toString()}`),
      api.get<ConnectorInstanceSummary[]>("/connector-instances"),
    ]);
    feed = feedResp;
    connectors = connectorResp;
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 422) {
      return (
        <div>
          <PageHeader
            title="Changes"
            description="What moved across your connected apps, ranked by how much it matters."
          />
          <EmptyState
            title="That filter isn't valid"
            hint="Clear the filters and try again."
            action={
              <Button asChild variant="outline" size="sm">
                <Link href="/changes">Reset filters</Link>
              </Button>
            }
          />
        </div>
      );
    }
    throw error;
  }

  const classes = Object.entries(feed.summary.by_class)
    .sort((a, b) => b[1] - a[1])
    .map(([id]) => id);
  const hasFilter = Boolean(
    filters.change_class ||
      (filters.min_significance && filters.min_significance !== "medium") ||
      filters.search?.trim() ||
      filters.person ||
      filters.app ||
      filters.connector_instance_id,
  );

  return (
    <div>
      <PageHeader
        eyebrow="Investigation feed"
        title="Changes"
        description="What moved across your connected apps, ranked by how much it matters. Each integration's first sync is the baseline, not a change."
        status={
          feed.total > 0 ? (
            <Badge variant="outline" className="font-mono">
              {feed.total}
            </Badge>
          ) : null
        }
      />

      <ChangesSearchBar filters={filters} connectors={connectors} classes={classes} />

      {feed.scan_saturated ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
          <p>
            More changes exist in this window than the feed scans at once. Narrow the window or
            search for a person / app to see matching rows beyond the browse cap.
          </p>
        </div>
      ) : null}

      {feed.changes.length === 0 ? (
        <EmptyState
          title={hasFilter ? "No changes match these filters" : "No changes in this window"}
          hint={
            hasFilter
              ? "Try a wider window or clear the filters."
              : "An integration's first sync establishes the baseline, so changes appear from its second sync onward."
          }
          action={
            hasFilter ? (
              <Button asChild size="sm" variant="outline">
                <Link href="/changes">Clear filters</Link>
              </Button>
            ) : (
              <Button asChild size="sm">
                <Link href="/connectors">Open Integrations</Link>
              </Button>
            )
          }
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="max-h-[70vh] overflow-auto">
            <TooltipProvider delayDuration={200}>
              <Table>
                <TableHeader>
                  <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
                    <TableHead>Change</TableHead>
                    <TableHead>Class</TableHead>
                    <TableHead>Before → after</TableHead>
                    <TableHead>Detected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feed.changes.map((change) => (
                    <ChangeRow key={change.event_id} change={change} />
                  ))}
                </TableBody>
              </Table>
            </TooltipProvider>
          </div>
        </Card>
      )}

      <p className="mt-4 text-xs text-muted-foreground">
        Showing {feed.changes.length} of {feed.total} since <LocalTime value={feed.since} />.
        Kestrel records the tenant at each successful sync. Actions granted and fully reversed
        between syncs will not appear here. Where a connector collects an audit log, the person
        who made the change is shown on the row; rows without one were still detected, just not
        attributed.
      </p>
    </div>
  );
}
