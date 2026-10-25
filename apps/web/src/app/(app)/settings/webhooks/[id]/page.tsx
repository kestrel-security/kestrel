// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound, unstable_rethrow } from "next/navigation";

import { FilterChip } from "@/components/ui/filter-chip";
import { SettingsSection } from "@/components/settings/settings-section";
import { DeleteWebhookButton, WebhookToggleButton } from "@/components/settings/webhook-actions";
import { RotateWebhookSecretButton } from "@/components/settings/rotate-webhook-secret-button";
import { WebhookDeliveriesTable } from "@/components/settings/webhook-deliveries-table";
import { StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, api, segment } from "@/lib/api";
import { clearFiltersHref, filterHref } from "@/lib/list-filters";
import type { Operator, WebhookDelivery, WebhookEndpoint } from "@/lib/types";

const STATUS_FILTERS = ["pending", "success", "failed"] as const;

export default async function WebhookDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ status?: string }>;
}) {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const { id } = await params;
  const { status: statusRaw } = await searchParams;
  const statusFilter =
    statusRaw && STATUS_FILTERS.includes(statusRaw as (typeof STATUS_FILTERS)[number])
      ? statusRaw
      : undefined;

  let hook: WebhookEndpoint;
  try {
    hook = await api.get<WebhookEndpoint>(`/webhooks/${segment(id)}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }

  const query = new URLSearchParams();
  query.set("limit", "100");
  if (statusFilter) query.set("status", statusFilter);

  let deliveries: WebhookDelivery[] = [];
  try {
    deliveries = await api.get<WebhookDelivery[]>(
      `/webhooks/${segment(id)}/deliveries?${query.toString()}`,
    );
  } catch (error) {
    unstable_rethrow(error);
    deliveries = [];
  }

  const counts = hook.delivery_counts ?? { pending: 0, success: 0, failed: 0 };
  const current = new URLSearchParams();
  if (statusFilter) current.set("status", statusFilter);

  return (
    <div className="space-y-6">
      <div>
        <p className="mb-1 text-sm text-muted-foreground">
          <Link href="/settings/webhooks" className="hover:underline">
            Webhooks
          </Link>{" "}
          / {hook.name}
        </p>
        <SettingsSection
          eyebrow="Settings"
          title={hook.name}
          description={
            <span className="space-y-1">
              <span className="block break-all font-mono text-xs">{hook.url}</span>
              <span className="block text-xs">Events: {hook.events.join(", ")}</span>
              {hook.description ? <span className="block">{hook.description}</span> : null}
            </span>
          }
          actions={<StatusBadge status={hook.is_enabled ? "enabled" : "disabled"} />}
        />
      </div>

      <div className="flex flex-wrap items-start gap-2">
        <WebhookToggleButton webhookId={hook.id} isEnabled={hook.is_enabled} />
        <RotateWebhookSecretButton webhookId={hook.id} />
        <DeleteWebhookButton
          webhookId={hook.id}
          name={hook.name}
          redirectAfter="/settings/webhooks"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Delivery history</CardTitle>
          <CardDescription>
            {counts.success} success · {counts.failed} failed · {counts.pending} pending
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-muted-foreground">Status:</span>
            <FilterChip
              href={clearFiltersHref(`/settings/webhooks/${id}`)}
              active={!statusFilter}
              label="All"
            />
            {STATUS_FILTERS.map((s) => (
              <FilterChip
                key={s}
                href={filterHref(`/settings/webhooks/${id}`, current, "status", s)}
                active={statusFilter === s}
                label={s}
                count={s === "failed" && counts.failed > 0 ? counts.failed : undefined}
              />
            ))}
          </div>
          <WebhookDeliveriesTable webhookId={hook.id} deliveries={deliveries} />
        </CardContent>
      </Card>
    </div>
  );
}
