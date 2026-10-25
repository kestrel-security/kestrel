// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { notFound } from "next/navigation";

import { SettingsSection } from "@/components/settings/settings-section";
import { DeleteWebhookButton, WebhookToggleButton } from "@/components/settings/webhook-actions";
import { RotateWebhookSecretButton } from "@/components/settings/rotate-webhook-secret-button";
import { WebhookCreateForm } from "@/components/settings/webhook-create-form";
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
import type { Operator, WebhookEndpoint } from "@/lib/types";
import { countOf } from "@/lib/plural";

function formatCounts(hook: WebhookEndpoint): string {
  const c = hook.delivery_counts;
  if (!c) return "—";
  const total = c.pending + c.success + c.failed;
  if (total === 0) return "No deliveries yet";
  const parts = [`${c.success} ok`];
  if (c.failed) parts.push(`${c.failed} failed`);
  if (c.pending) parts.push(`${c.pending} pending`);
  return parts.join(" · ");
}

export default async function WebhooksSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const webhooks = await api.get<WebhookEndpoint[]>("/webhooks");
  const orgFailed = webhooks.reduce((n, h) => n + (h.delivery_counts?.failed ?? 0), 0);
  const orgPending = webhooks.reduce((n, h) => n + (h.delivery_counts?.pending ?? 0), 0);
  const endpointsWithFailures = webhooks.filter((h) => (h.delivery_counts?.failed ?? 0) > 0).length;

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Webhooks"
        description="Outbound HTTPS callbacks when findings open or resolve. Payloads are HMAC-SHA256 signed; the signing secret is shown only once on create or rotate."
      />

      {orgFailed + orgPending > 0 ? (
        <div
          className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
          role="status"
        >
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
          <div>
            <p className="font-medium">
              {countOf(orgFailed, "failed delivery", "failed deliveries")}
              {endpointsWithFailures > 0
                ? ` across ${countOf(endpointsWithFailures, "endpoint")}`
                : ""}
              {orgPending > 0 ? ` · ${orgPending} pending` : ""}
            </p>
            <p className="mt-1 text-xs opacity-90">
              Open an endpoint below, filter to Failed, and use Retry to re-drive stuck deliveries.
            </p>
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Endpoints</CardTitle>
          <CardDescription>
            Open an endpoint for delivery history and failed-delivery retry.
          </CardDescription>
        </CardHeader>
        <CardContent className={webhooks.length === 0 ? undefined : "overflow-x-auto p-0"}>
          {webhooks.length === 0 ? (
            <EmptyState
              title="No webhooks configured yet"
              hint="Add an HTTPS endpoint below to receive finding.opened and finding.resolved events."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 hover:bg-muted/40">
                  <TableHead>Name</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Deliveries</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {webhooks.map((hook) => {
                  const failed = hook.delivery_counts?.failed ?? 0;
                  return (
                    <TableRow key={hook.id}>
                      <TableCell className="align-top">
                        <Link
                          href={`/settings/webhooks/${hook.id}`}
                          className="font-medium hover:underline"
                        >
                          {hook.name}
                        </Link>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          {hook.events.join(", ")}
                        </p>
                        {hook.description ? (
                          <p className="mt-1 text-xs text-muted-foreground">{hook.description}</p>
                        ) : null}
                      </TableCell>
                      <TableCell className="max-w-[14rem] break-all align-top font-mono text-xs text-muted-foreground">
                        {hook.url}
                      </TableCell>
                      <TableCell className="align-top">
                        <StatusBadge status={hook.is_enabled ? "enabled" : "disabled"} />
                      </TableCell>
                      <TableCell className="align-top text-xs text-muted-foreground">
                        {formatCounts(hook)}
                        {failed > 0 ? (
                          <div className="mt-1">
                            <Link
                              href={`/settings/webhooks/${hook.id}?status=failed`}
                              className="text-destructive underline-offset-2 hover:underline"
                            >
                              View failures
                            </Link>
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="align-top">
                        <div className="flex flex-col items-start gap-2">
                          <div className="flex flex-wrap gap-2">
                            <Link
                              href={`/settings/webhooks/${hook.id}`}
                              className="rounded-md border border-border px-2 py-1 text-xs hover:bg-muted"
                            >
                              Deliveries
                            </Link>
                            <WebhookToggleButton
                              webhookId={hook.id}
                              isEnabled={hook.is_enabled}
                            />
                            <DeleteWebhookButton webhookId={hook.id} name={hook.name} />
                          </div>
                          <RotateWebhookSecretButton webhookId={hook.id} />
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Add endpoint</CardTitle>
          <CardDescription>
            The signing secret is shown once after create. Store it with your receiver.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <WebhookCreateForm />
        </CardContent>
      </Card>
    </div>
  );
}
