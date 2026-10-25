// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Loader2, PlayCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import type { PolicyDryRunResult } from "@/lib/types";

import { PanelEmpty, StaleNotice } from "./stale-notice";
import { countOf } from "@/lib/plural";

export function DryRunPanel({
  result,
  stale,
  error,
  busy,
  capturing,
  onRerun,
  onCapture,
}: {
  result: PolicyDryRunResult | null;
  stale: boolean;
  error?: string;
  busy: boolean;
  capturing: boolean;
  onRerun: () => void;
  onCapture: () => void;
}) {
  return (
    <div className="space-y-3">
      {error ? <Callout tone="error">{error}</Callout> : null}
      {stale ? <StaleNotice onRerun={onRerun} rerunLabel="Re-run dry-run" busy={busy} /> : null}
      {!result ? (
        <PanelEmpty>
          Click <span className="font-medium text-foreground">Dry-run on live inventory</span> to
          preview which subjects would match right now. Nothing is persisted.
        </PanelEmpty>
      ) : (
        <div className="space-y-2 text-sm">
          <p className="flex items-center gap-2 font-medium">
            <PlayCircle className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            Live dry-run — {countOf(result.match_count, "match", "matches")}
            {result.truncated ? " (truncated)" : ""} · {result.new_match_count} new ·{" "}
            {result.existing_match_count} already open · {result.would_resolve_count} would resolve ·{" "}
            {result.duration_ms}ms
          </p>
          <p className="text-xs text-muted-foreground">
            Preview only — nothing was persisted. Enable the policy (or sync) to write findings.
          </p>
          {result.matches.length > 0 ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onCapture}
              disabled={capturing}
            >
              {capturing ? <Loader2 className="animate-spin" aria-hidden /> : null}
              Save matching subjects as fixture
            </Button>
          ) : null}
          {result.matches.length === 0 ? (
            <p className="text-muted-foreground">No matches against current inventory.</p>
          ) : (
            <ul className="space-y-1 text-xs">
              {result.matches.map((m) => (
                <li key={`${m.subject_type}-${m.subject_id}-${m.match_status}`}>
                  <span className="font-medium">{m.label || m.subject_id}</span>
                  <span className="text-muted-foreground">
                    {" "}
                    · {m.subject_type} · {m.match_status}
                  </span>
                  {m.existing_finding_path ? (
                    <a href={m.existing_finding_path} className="ml-2 text-primary underline">
                      finding →
                    </a>
                  ) : m.detail_path ? (
                    <a href={m.detail_path} className="ml-2 text-primary underline">
                      detail →
                    </a>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          {result.would_resolve.length > 0 ? (
            <div>
              <p className="text-xs font-medium text-muted-foreground">Would auto-resolve</p>
              <ul className="mt-1 space-y-1 text-xs">
                {result.would_resolve.slice(0, 20).map((m) => (
                  <li key={`resolve-${m.existing_finding_id}`}>
                    {m.label || m.subject_id}
                    {m.existing_finding_path ? (
                      <a href={m.existing_finding_path} className="ml-2 text-primary underline">
                        finding →
                      </a>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
