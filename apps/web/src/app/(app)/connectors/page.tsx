// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { Badge, StatusBadge } from "@/components/ui/badge";
import { SyncNowButton } from "@/components/connectors/sync-now-button";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
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
import { api, orFallback } from "@/lib/api";
import { absoluteTime, relativeTime } from "@/lib/utils";
import type { ConnectorCatalogEntry, ConnectorInstanceSummary } from "@/lib/types";

const BUILTIN_FALLBACK = new Set([
  "github",
  "okta",
  "google_workspace",
  "slack",
]);

function catalogKind(
  connectorName: string | null,
  sourceByName: Map<string, string>,
): "builtin" | "custom" {
  if (!connectorName) return "custom";
  const source = sourceByName.get(connectorName);
  if (source === "custom" || source === "community") return "custom";
  if (source === "builtin") return "builtin";
  return BUILTIN_FALLBACK.has(connectorName) ? "builtin" : "custom";
}

export default async function ConnectorsPage() {
  let instances: ConnectorInstanceSummary[] = [];
  let catalog: ConnectorCatalogEntry[] = [];
  try {
    [instances, catalog] = await Promise.all([
      api.get<ConnectorInstanceSummary[]>("/connector-instances"),
      api.get<ConnectorCatalogEntry[]>("/connectors").catch(orFallback([] as ConnectorCatalogEntry[])),
    ]);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const sourceByName = new Map(
    catalog.map((entry) => [entry.name, entry.source ?? "builtin"] as const),
  );

  return (
    <div>
      <PageHeader
        eyebrow="Integrations"
        title="Integrations"
        description="Fleet view of your integrations — health, last sync, and schedule. Open an integration for secrets, schedule editing, and full run history."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href="/connectors/health">Integration health</Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/connectors/new">Add integration</Link>
            </Button>
          </>
        }
      />

      {instances.length === 0 ? (
        <EmptyState
          title="No integrations configured yet"
          hint="Add an integration from the UI, or create one via the API."
          action={
            <Button asChild size="sm">
              <Link href="/connectors/new">Add integration</Link>
            </Button>
          }
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="max-h-[70vh] overflow-auto">
            <Table>
              <TableHeader>
                <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
                  <TableHead>Name</TableHead>
                  <TableHead>App / type</TableHead>
                  <TableHead>Health</TableHead>
                  <TableHead>Last sync</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {instances.map((instance) => (
                  <ConnectorFleetRow
                    key={instance.id}
                    instance={instance}
                    kind={catalogKind(instance.connector_name, sourceByName)}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        </Card>
      )}
    </div>
  );
}

function ConnectorFleetRow({
  instance,
  kind,
}: {
  instance: ConnectorInstanceSummary;
  kind: "builtin" | "custom";
}) {
  const title =
    instance.application_display_name ||
    instance.connector_display_name ||
    instance.connector_name ||
    instance.id;

  const typeLabel =
    instance.connector_display_name || instance.connector_name || "Unknown";
  const healthStatus = instance.health || instance.last_run_status;
  const lastSync = instance.last_success_at || instance.last_run_at;
  const secretsMissing =
    instance.secrets &&
    instance.secrets.missing_fields.length > 0 &&
    instance.sync_mode === "live";

  return (
    <TableRow>
      <TableCell>
        <Link href={`/connectors/${instance.id}`} className="font-medium hover:underline">
          {title}
        </Link>
        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          <span>{instance.external_tenant_ref || typeLabel}</span>
          {/* Sync mode only earns space when it is the surprising one: a
              fixture-backed connector is showing sample data, and an operator
              looking at a finding needs to know that. */}
          {instance.sync_mode === "fixtures" ? (
            <Badge className="bg-muted text-muted-foreground">Sample data</Badge>
          ) : null}
          {secretsMissing ? (
            <span className="text-amber-700 dark:text-amber-300">· secrets missing</span>
          ) : null}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground">{typeLabel}</span>
          <Badge
            className={
              kind === "custom"
                ? "bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200"
                : "bg-muted text-muted-foreground"
            }
          >
            {kind === "custom" ? "Custom" : "Built-in"}
          </Badge>
        </div>
      </TableCell>
      <TableCell>
        {healthStatus ? (
          <StatusBadge status={healthStatus} />
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell className="tabular-nums text-muted-foreground" title={absoluteTime(lastSync)}>
        {relativeTime(lastSync, undefined, "Never")}
      </TableCell>
      <TableCell>
        {instance.schedule_cron ? (
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
            {instance.schedule_cron}
          </code>
        ) : (
          <span className="text-muted-foreground">Manual</span>
        )}
      </TableCell>
      <TableCell className="text-right">
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={`/connectors/${instance.id}`}>Configure</Link>
          </Button>
          <SyncNowButton connectorInstanceId={instance.id} variant="secondary" compact isDemo={instance.is_demo} />
        </div>
      </TableCell>
    </TableRow>
  );
}
