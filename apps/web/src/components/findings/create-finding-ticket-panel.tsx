// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { FlaskConical, Ticket } from "lucide-react";

import { Button } from "@/components/ui/button";
import { createFindingTicket } from "@/lib/actions/findings";
import type { FindingTicketRef, TicketIntegration } from "@/lib/types";

const CAP = 10;

type Props = {
  findingId: string;
  tickets: FindingTicketRef[];
  integrations: TicketIntegration[];
  canCreate: boolean;
};

export function CreateFindingTicketPanel({
  findingId,
  tickets,
  integrations,
  canCreate,
}: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [dryRunUrl, setDryRunUrl] = useState<string | null>(null);
  const [integrationId, setIntegrationId] = useState("");
  const enabled = integrations.filter((i) => i.is_enabled);
  const atCap = tickets.length >= CAP;

  function submit(dryRun: boolean) {
    setError(null);
    setDryRunUrl(null);
    if (!integrationId) {
      setError("Choose an integration");
      return;
    }
    startTransition(async () => {
      const result = await createFindingTicket(findingId, {
        integration_id: integrationId,
        dry_run: dryRun,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      if (result.dry_run) {
        setDryRunUrl(result.url);
        return;
      }
      router.refresh();
    });
  }

  return (
    <div className="space-y-4">
      {tickets.length > 0 ? (
        <ul className="space-y-2 text-sm">
          {tickets.map((t) => (
            <li key={t.id} className="flex flex-wrap items-baseline gap-2">
              <Ticket className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
              <span className="text-xs text-muted-foreground">{t.provider}</span>
              <a
                href={t.url}
                target="_blank"
                rel="noreferrer"
                className="font-mono font-medium text-primary underline"
              >
                {t.external_id || t.url}
              </a>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">No tracker tickets linked yet.</p>
      )}

      {canCreate ? (
        enabled.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No enabled ticket integrations. Admins can add one under{" "}
            <Link href="/settings/ticketing" className="text-primary underline">
              Settings → Ticketing
            </Link>
            .
          </p>
        ) : atCap ? (
          <p className="text-sm text-muted-foreground">
            This finding already has {CAP} tickets (maximum).
          </p>
        ) : (
          <div className="space-y-2">
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            {dryRunUrl ? (
              <p className="text-xs text-muted-foreground">
                Dry-run URL (not created):{" "}
                <span className="break-all font-mono">{dryRunUrl}</span>
              </p>
            ) : null}
            <label className="block text-xs text-muted-foreground">
              Integration
              <select
                value={integrationId}
                onChange={(e) => setIntegrationId(e.target.value)}
                className="mt-1 w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                disabled={pending}
              >
                <option value="">Choose…</option>
                {enabled.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name} ({i.provider})
                  </option>
                ))}
              </select>
            </label>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" disabled={pending} onClick={() => submit(false)}>
                <Ticket aria-hidden />
                {pending ? "Working…" : "Create ticket"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={pending}
                onClick={() => submit(true)}
              >
                <FlaskConical aria-hidden />
                Dry-run
              </Button>
            </div>
          </div>
        )
      ) : (
        <p className="text-xs text-muted-foreground">Analyst role required to create tickets.</p>
      )}
    </div>
  );
}
