// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState } from "react";
import { RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { FindingVerifyResult } from "@/lib/types";

export function VerifyRemediationButton({ findingId }: { findingId: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<FindingVerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncToo, setSyncToo] = useState(false);

  async function runVerify() {
    setStatus("loading");
    setError(null);
    try {
      const response = await fetch(`/api/findings/${findingId}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trigger_sync: syncToo }),
        cache: "no-store",
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { detail?: string } | null;
        setError(body?.detail || `Verify failed (${response.status})`);
        setStatus("error");
        return;
      }
      const body = (await response.json()) as FindingVerifyResult;
      setResult(body);
      setStatus("done");
    } catch {
      setError("Verify failed — network error");
      setStatus("error");
    }
  }

  return (
    <div id="verify" className="space-y-3 rounded-md border border-border bg-muted/30 px-3 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium">Verify remediation</p>
          <p className="text-xs text-muted-foreground">
            Dry-run this finding&apos;s policy on live inventory for this subject. Does not change
            finding status.
          </p>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={status === "loading"}
          onClick={() => void runVerify()}
        >
          <RefreshCw aria-hidden className={cn(status === "loading" && "animate-spin")} />
          {status === "loading" ? "Checking…" : "Re-check now"}
        </Button>
      </div>
      <label className="flex items-center gap-2 text-xs text-muted-foreground">
        <input
          type="checkbox"
          checked={syncToo}
          onChange={(e) => setSyncToo(e.target.checked)}
          className="rounded border-border"
        />
        Also enqueue an integration sync after check (when resolvable)
      </label>
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {result ? (
        <div className="space-y-1 text-sm">
          <p>
            <span className="font-medium">Result: </span>
            <code className="rounded bg-muted px-1 font-mono">{result.result}</code>
          </p>
          <p className="text-muted-foreground">{result.message}</p>
          {result.sync_enqueued ? (
            <p className="text-xs text-muted-foreground">
              Sync enqueued (task {result.sync_enqueued.task_id}).
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
