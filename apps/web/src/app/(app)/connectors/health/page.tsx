// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { StatusBadge } from "@/components/ui/badge";
import { SyncNowButton } from "@/components/connectors/sync-now-button";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterChip } from "@/components/ui/filter-chip";
import { PageHeader } from "@/components/ui/page-header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiStatePage } from "@/components/api-state";
import { api } from "@/lib/api";
import { filterHref } from "@/lib/list-filters";
import type { ConnectorHealthCenter } from "@/lib/types";

const HEALTH_CHIPS = [
  { id: "failed", label: "Failed" },
  { id: "never", label: "Never synced" },
  { id: "stale", label: "Stale" },
  { id: "running", label: "Running" },
  { id: "healthy", label: "Healthy" },
] as const;

export default async function ConnectorHealthPage({
  searchParams,
}: {
  searchParams: Promise<{ health?: string; stale_after_hours?: string }>;
}) {
  const { health, stale_after_hours } = await searchParams;
  const query = new URLSearchParams();
  if (health && HEALTH_CHIPS.some((c) => c.id === health)) {
    query.set("health", health);
  }
  if (stale_after_hours && /^\d+$/.test(stale_after_hours)) {
    query.set("stale_after_hours", stale_after_hours);
  }
  const qs = query.toString();

  let center: ConnectorHealthCenter;
  try {
    center = await api.get<ConnectorHealthCenter>(
      `/connector-instances/health${qs ? `?${qs}` : ""}`,
    );
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const current = new URLSearchParams();
  if (health && HEALTH_CHIPS.some((c) => c.id === health)) current.set("health", health);
  if (stale_after_hours && /^\d+$/.test(stale_after_hours)) {
    current.set("stale_after_hours", stale_after_hours);
  }
  const hasFilter = Boolean(health);

  return (
    <div>
      <PageHeader
        eyebrow="Integrations"
        title="Integration health"
        description={`Sync freshness and failure queues, plus a labeled 7-day success / freshness strip (not an opaque score). Stale means last successful sync is older than ${center.stale_after_hours}h.`}
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href="/connectors">All integrations</Link>
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        {HEALTH_CHIPS.map((chip) => (
          <FilterChip
            key={chip.id}
            href={filterHref("/connectors/health", current, "health", chip.id)}
            active={health === chip.id}
            label={chip.label}
            count={center.summary[chip.id] ?? 0}
          />
        ))}
        {hasFilter ? (
          <Link
            href="/connectors/health"
            className="ml-1 text-xs text-muted-foreground hover:underline"
          >
            Reset filter
          </Link>
        ) : null}
      </div>

      {center.slo ? (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <SloTile
            label={`${center.slo.window_days}d sync success`}
            value={
              center.slo.success_rate_pct == null
                ? "—"
                : `${center.slo.success_rate_pct}%`
            }
            hint={`${center.slo.runs_success}/${center.slo.runs_total} runs · target ≥${center.slo.success_target_pct}%`}
            met={center.slo.success_slo_met}
            empty={center.slo.runs_total === 0}
          />
          <SloTile
            label="Instance freshness"
            value={
              center.slo.freshness_pct == null ? "—" : `${center.slo.freshness_pct}%`
            }
            hint={`${center.slo.instances_healthy} healthy · ${center.slo.instances_degraded} degraded / ${center.slo.instances_total} · target ≥${center.slo.freshness_target_pct}%`}
            met={center.slo.freshness_slo_met}
            empty={center.slo.instances_total === 0}
          />
          <SloTile
            label="Failed runs (window)"
            value={String(center.slo.runs_failed)}
            hint={
              center.slo.runs_degraded > 0
                ? `${center.slo.runs_degraded} more ran with reduced coverage`
                : "runs that did not complete"
            }
            met={center.slo.runs_failed === 0}
            empty={false}
          />
          <SloTile
            label="Unhealthy instances"
            value={String(center.slo.instances_unhealthy)}
            hint="excludes in-flight running"
            met={center.slo.instances_unhealthy === 0}
            empty={false}
          />
        </div>
      ) : null}

      {center.items.length === 0 ? (
        <EmptyState
          title={hasFilter ? "No integrations match this health filter" : "No integrations configured yet"}
          hint={
            hasFilter
              ? "Try another health chip or clear the filter."
              : "Add an integration from Integrations → Add integration."
          }
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="max-h-[70vh] overflow-auto">
            <Table>
              <TableHeader>
                <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
                  <TableHead>Application</TableHead>
                  <TableHead>Health</TableHead>
                  <TableHead>Last success</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {center.items.map((row) => (
                  <HealthRow key={row.id} row={row} />
                ))}
              </TableBody>
            </Table>
          </div>
        </Card>
      )}
    </div>
  );
}

function SloTile({
  label,
  value,
  hint,
  met,
  empty,
}: {
  label: string;
  value: string;
  hint: string;
  met: boolean;
  empty: boolean;
}) {
  return (
    <Card className="px-3 py-2.5">
      <p className="text-eyebrow">{label}</p>
      <p className="mt-1.5 text-xl font-semibold tabular-nums">{value}</p>
      <p className="mt-1 text-[11px] text-muted-foreground">
        {empty ? "no data in window" : met ? `on target · ${hint}` : hint}
      </p>
    </Card>
  );
}

function HealthRow({ row }: { row: ConnectorHealthCenter["items"][number] }) {
  const title =
    row.application_display_name ||
    row.connector_display_name ||
    row.connector_name ||
    row.id;
  const successLabel = row.last_success_at
    ? row.hours_since_success != null
      ? `${row.hours_since_success}h ago`
      : row.last_success_at
    : "—";

  return (
    <TableRow>
      <TableCell>
        <div className="font-medium">{title}</div>
        <div className="text-xs text-muted-foreground">
          {row.connector_name}
          {row.error_summary ? ` · ${row.error_summary}` : ""}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={row.health} />
          {row.last_run_status && row.last_run_status !== row.health ? (
            <span className="text-xs text-muted-foreground">run: {row.last_run_status}</span>
          ) : null}
        </div>
      </TableCell>
      <TableCell className="tabular-nums text-muted-foreground">{successLabel}</TableCell>
      <TableCell className="text-muted-foreground">
        {row.schedule_cron ? (
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
            {row.schedule_cron}
          </code>
        ) : (
          "none"
        )}
      </TableCell>
      <TableCell className="text-right">
        <div className="flex flex-wrap justify-end gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={`/connectors/${row.id}`}>Integration</Link>
          </Button>
          <SyncNowButton connectorInstanceId={row.id} variant="secondary" compact isDemo={row.is_demo} />
        </div>
      </TableCell>
    </TableRow>
  );
}
