// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEffect, useState, useTransition } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

import { Button } from "@/components/ui/button";
import { LocalTime } from "@/components/ui/local-time";
import { fetchFindingProvenance } from "@/lib/actions/findings";
import type { FindingProvenance } from "@/lib/types";

export function FindingProvenanceBrowser({ findingId }: { findingId: string }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<FindingProvenance | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    if (!open || data || pending) return;
    startTransition(async () => {
      const result = await fetchFindingProvenance(findingId);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setData(result.provenance);
    });
  }, [open, data, pending, findingId]);

  return (
    <div className="space-y-2">
      <Button type="button" size="sm" variant="outline" onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronUp aria-hidden /> : <ChevronDown aria-hidden />}
        {open ? "Hide provider payload" : "Browse subject raw_source"}
      </Button>
      {open && (
        <div className="rounded-md border border-border bg-muted/30 p-3">
          {pending && !data && !error ? (
            <p className="text-sm text-muted-foreground">Loading provenance…</p>
          ) : null}
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
          {data ? (
            <div className="space-y-2 text-sm">
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span>
                  {data.subject_type} · {data.available ? "available" : "unavailable"}
                </span>
                {data.trimmed ? (
                  <span className="rounded bg-amber-100 px-1.5 py-0.5 text-amber-900 dark:bg-amber-950/40 dark:text-amber-100">
                    trimmed
                  </span>
                ) : null}
                {data.truncated ? (
                  <span className="rounded bg-amber-100 px-1.5 py-0.5 text-amber-900 dark:bg-amber-950/40 dark:text-amber-100">
                    truncated
                  </span>
                ) : null}
                {data.approx_bytes > 0 ? <span>~{data.approx_bytes.toLocaleString()} bytes</span> : null}
                {data.last_seen_at ? (
                  <span>last seen <LocalTime value={data.last_seen_at} /></span>
                ) : null}
              </div>
              {data.message && data.message !== "truncated" ? (
                <p className="text-xs text-muted-foreground">{data.message}</p>
              ) : null}
              {data.raw_source ? (
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-2 font-mono text-xs">
                  {JSON.stringify(data.raw_source, null, 2)}
                </pre>
              ) : (
                <p className="text-sm text-muted-foreground">No raw_source payload for this subject.</p>
              )}
              <p className="text-xs text-muted-foreground">
                Secret-looking keys are redacted. Trimmed payloads show a tombstone only.
              </p>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
