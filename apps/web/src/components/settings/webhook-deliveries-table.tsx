// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { RetryWebhookDeliveryButton } from "@/components/settings/retry-webhook-delivery-button";
import { StatusBadge } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { WebhookDelivery } from "@/lib/types";

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function WebhookDeliveriesTable({
  webhookId,
  deliveries,
}: {
  webhookId: string;
  deliveries: WebhookDelivery[];
}) {
  if (deliveries.length === 0) {
    return <p className="text-sm text-muted-foreground">No deliveries match this filter.</p>;
  }

  return (
    <div className="max-h-[32rem] overflow-auto rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
            <TableHead>When</TableHead>
            <TableHead>Event</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>HTTP</TableHead>
            <TableHead>Latency</TableHead>
            <TableHead>Attempts</TableHead>
            <TableHead>Finding</TableHead>
            <TableHead>Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {deliveries.map((d) => (
            <TableRow key={d.id}>
              <TableCell className="whitespace-nowrap align-top text-xs text-muted-foreground">
                <LocalTime value={d.created_at} />
              </TableCell>
              <TableCell className="align-top font-mono text-xs">{d.event_type}</TableCell>
              <TableCell className="align-top">
                <StatusBadge status={d.status} />
                {d.error_message && (
                  <p className="mt-1 max-w-xs break-words text-xs text-muted-foreground">
                    {d.error_message}
                  </p>
                )}
              </TableCell>
              <TableCell className="align-top font-mono text-xs">{d.http_status ?? "—"}</TableCell>
              <TableCell className="align-top font-mono text-xs">{formatLatency(d.latency_ms)}</TableCell>
              <TableCell className="align-top font-mono text-xs">{d.attempt_count}</TableCell>
              <TableCell className="align-top text-xs">
                {d.finding_id ? (
                  <Link
                    href={`/findings/${d.finding_id}`}
                    className="font-mono text-foreground underline-offset-2 hover:underline"
                  >
                    {d.finding_id.slice(0, 8)}…
                  </Link>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="align-top">
                {d.can_retry ? (
                  <RetryWebhookDeliveryButton webhookId={webhookId} deliveryId={d.id} />
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
