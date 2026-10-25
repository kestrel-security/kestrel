// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound, unstable_rethrow } from "next/navigation";

import { ConnectorEditForm } from "@/components/connectors/connector-edit-form";
import { ConnectorRunHistory } from "@/components/connectors/connector-run-history";
import { ConnectorScheduleForm } from "@/components/connectors/connector-schedule-form";
import { ConnectorSetupGuide } from "@/components/connectors/connector-setup-guide";
import { DeleteConnectorButton } from "@/components/connectors/delete-connector-button";
import { SyncNowButton } from "@/components/connectors/sync-now-button";
import { TestConnectionButton } from "@/components/connectors/test-connection-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { apiStatePage } from "@/components/api-state";
import { ApiError, api, segment } from "@/lib/api";
import type { ConnectorCatalogEntry, ConnectorInstanceDetail, ConnectorRun } from "@/lib/types";

export default async function ConnectorDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let detail: ConnectorInstanceDetail;
  let catalog: ConnectorCatalogEntry[] = [];
  let runs: ConnectorRun[] = [];
  try {
    detail = await api.get<ConnectorInstanceDetail>(`/connector-instances/${segment(id)}`);
    catalog = await api.get<ConnectorCatalogEntry[]>("/connectors");
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  try {
    runs = await api.get<ConnectorRun[]>(`/connector-instances/${segment(id)}/runs?limit=50`);
  } catch (error) {
    unstable_rethrow(error);
    runs = [];
  }

  const catalogEntry = catalog.find((c) => c.name === detail.connector_name) ?? null;
  const authMethod =
    catalogEntry?.auth_methods.find((m) => m.id === detail.auth_method) ??
    catalogEntry?.auth_methods[0] ??
    null;

  const title =
    detail.application_display_name ||
    detail.connector_display_name ||
    detail.connector_name ||
    detail.id;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <p className="text-sm text-muted-foreground">
        <Link href="/connectors" className="hover:underline">
          Integrations
        </Link>{" "}
        / {title}
      </p>
      <PageHeader
        eyebrow="Integrations"
        title={title}
        status={detail.health && <StatusBadge status={detail.health} />}
        description={`${detail.connector_name} · Auth: ${detail.auth_method} · Mode: ${detail.sync_mode}`}
        className="mb-0"
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(16rem,20rem)]">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Connection</CardTitle>
              <CardDescription>Verify credentials and trigger a sync on demand.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-3">
              <TestConnectionButton connectorInstanceId={detail.id} />
              <SyncNowButton connectorInstanceId={detail.id} isDemo={detail.is_demo} />
              <DeleteConnectorButton connectorInstanceId={detail.id} displayName={title} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Builder</CardTitle>
              <CardDescription>Config fields and secrets from the connector manifest.</CardDescription>
            </CardHeader>
            <CardContent>
              <ConnectorEditForm detail={detail} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Schedule</CardTitle>
              <CardDescription>Standard 5-field cron (UTC). Missed fires are not backfilled.</CardDescription>
            </CardHeader>
            <CardContent>
              <ConnectorScheduleForm
                connectorInstanceId={detail.id}
                initialSchedule={detail.schedule_cron}
              />
            </CardContent>
          </Card>

          <Card id="runs">
            <CardHeader>
              <CardTitle>Run history</CardTitle>
              <CardDescription>Latest sync runs for this instance.</CardDescription>
            </CardHeader>
            <CardContent>
              <ConnectorRunHistory runs={runs} instanceId={detail.id} />
              {runs.length >= 50 ? (
                <p className="mt-2 text-xs text-muted-foreground">Showing the latest 50 runs.</p>
              ) : null}
            </CardContent>
          </Card>
        </div>

        <div className="lg:sticky lg:top-4 lg:self-start">
          <ConnectorSetupGuide connector={catalogEntry} authMethod={authMethod} />
        </div>
      </div>
    </div>
  );
}
