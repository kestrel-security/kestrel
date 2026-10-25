// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound } from "next/navigation";

import { SettingsSection } from "@/components/settings/settings-section";
import {
  DeleteTicketIntegrationButton,
  TicketToggleButton,
} from "@/components/settings/ticket-actions";
import { RotateTicketTokenButton } from "@/components/settings/rotate-ticket-token-button";
import { TicketIntegrationCreateForm } from "@/components/settings/ticket-integration-create-form";
import { StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api";
import type { Operator, TicketIntegration } from "@/lib/types";

const PROVIDER_LABELS: Record<string, string> = {
  github_issues: "GitHub Issues",
  jira_cloud: "Jira Cloud",
};

function providerLabel(provider: string): string {
  return PROVIDER_LABELS[provider] ?? provider;
}

function configSummary(integration: TicketIntegration): string {
  const cfg = integration.config ?? {};
  if (integration.provider === "github_issues" && typeof cfg.repo === "string") {
    return cfg.repo;
  }
  if (integration.provider === "jira_cloud") {
    const base = typeof cfg.base_url === "string" ? cfg.base_url : "";
    const project = typeof cfg.project_key === "string" ? cfg.project_key : "";
    return [base, project].filter(Boolean).join(" · ");
  }
  return JSON.stringify(cfg);
}

export default async function TicketingSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const integrations = await api.get<TicketIntegration[]>("/ticket-integrations");

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Ticketing"
        description="Connect GitHub Issues or Jira Cloud so analysts can open tracker tickets from findings. API tokens are encrypted at rest and never shown again — rotate to replace."
      />

      <Card>
        <CardHeader>
          <CardTitle>Integrations</CardTitle>
          <CardDescription>
            Enabled integrations appear in the finding Create ticket panel.
          </CardDescription>
        </CardHeader>
        <CardContent className={integrations.length === 0 ? undefined : "overflow-x-auto p-0"}>
          {integrations.length === 0 ? (
            <EmptyState
              title="No ticket integrations configured yet"
              hint="Add GitHub Issues or Jira Cloud below so analysts can open tickets from findings."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 hover:bg-muted/40">
                  <TableHead>Name</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {integrations.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="align-top">
                      <div className="font-medium">{row.name}</div>
                      {row.description ? (
                        <p className="mt-0.5 text-xs text-muted-foreground">{row.description}</p>
                      ) : null}
                    </TableCell>
                    <TableCell className="align-top text-muted-foreground">
                      {providerLabel(row.provider)}
                    </TableCell>
                    <TableCell className="max-w-[14rem] break-all align-top font-mono text-xs text-muted-foreground">
                      {configSummary(row)}
                    </TableCell>
                    <TableCell className="align-top">
                      <StatusBadge status={row.is_enabled ? "enabled" : "disabled"} />
                    </TableCell>
                    <TableCell className="align-top">
                      <div className="flex flex-col items-start gap-2">
                        <div className="flex flex-wrap gap-2">
                          <TicketToggleButton integrationId={row.id} isEnabled={row.is_enabled} />
                          <DeleteTicketIntegrationButton integrationId={row.id} name={row.name} />
                        </div>
                        <RotateTicketTokenButton integrationId={row.id} />
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Add integration</CardTitle>
          <CardDescription>
            Tokens are envelope-encrypted. To replace one later, use Rotate token on the integration.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TicketIntegrationCreateForm />
        </CardContent>
      </Card>
    </div>
  );
}
