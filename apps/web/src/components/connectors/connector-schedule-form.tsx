// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";
import { updateConnectorSchedule } from "@/lib/actions/connectors";

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Every 15 minutes", value: "*/15 * * * *" },
  { label: "Every hour", value: "0 * * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at 02:00 UTC", value: "0 2 * * *" },
];

export function ConnectorScheduleForm({
  connectorInstanceId,
  initialSchedule,
}: {
  connectorInstanceId: string;
  initialSchedule: string | null;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [cron, setCron] = useState(initialSchedule ?? "");
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function save(next: string | null) {
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await updateConnectorSchedule(connectorInstanceId, next);
      if (!outcome.ok) {
        setError(outcome.error);
        toast("Could not save the schedule", { tone: "error", detail: outcome.error });
        return;
      }
      setCron(next ?? "");
      setNote(next ? "Schedule saved." : "Schedule cleared.");
      toast(next ? "Schedule saved" : "Schedule cleared", {
        detail: next ? `Syncs run on ${next} (UTC).` : "This integration now syncs only on demand.",
      });
      router.refresh();
    });
  }

  return (
    <div className="space-y-2">
      {error && <p className="text-xs text-destructive">{error}</p>}
      {note && <p className="text-xs text-green-700 dark:text-green-400">{note}</p>}
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={CRON_PRESETS.some((p) => p.value === cron) ? cron : "custom"}
          onValueChange={(value) => {
            if (value !== "custom") setCron(value);
          }}
          disabled={pending}
        >
          <SelectTrigger className="w-auto min-w-[10rem]">
            <SelectValue placeholder="Custom…" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="custom">Custom…</SelectItem>
            {CRON_PRESETS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          value={cron}
          onChange={(e) => setCron(e.target.value)}
          placeholder="*/30 * * * * or empty"
          className="min-w-[10rem] flex-1 font-mono"
          disabled={pending}
        />
        <Button type="button" variant="outline" size="sm" disabled={pending} onClick={() => save(cron.trim() || null)}>
          Save
        </Button>
        {initialSchedule && (
          <Button type="button" variant="outline" size="sm" disabled={pending} onClick={() => save(null)}>
            Clear
          </Button>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        {initialSchedule ? (
          <>
            Current: <code className="rounded bg-muted px-1 font-mono">{initialSchedule}</code>
          </>
        ) : (
          "No schedule — sync only when triggered manually."
        )}
      </p>
    </div>
  );
}
