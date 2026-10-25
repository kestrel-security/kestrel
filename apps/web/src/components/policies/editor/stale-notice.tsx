// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import type { ReactNode } from "react";
import { History, Loader2, RotateCw } from "lucide-react";

import { Button } from "@/components/ui/button";

/**
 * Shown when the editor content has drifted from what a result was computed
 * from. Results are kept and captioned rather than cleared — losing a dry-run's
 * match list because a comment was edited is worse than showing it with a
 * caveat.
 */
export function StaleNotice({
  message = "Source changed since this ran.",
  onRerun,
  rerunLabel,
  busy = false,
  disabled = false,
}: {
  message?: string;
  onRerun: () => void;
  rerunLabel: string;
  busy?: boolean;
  disabled?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border border-dashed bg-muted/30 px-2.5 py-1.5 text-xs text-muted-foreground">
      <History className="size-3.5 shrink-0" aria-hidden />
      <span>{message}</span>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-6 px-2 text-xs"
        onClick={onRerun}
        disabled={busy || disabled}
      >
        {busy ? (
          <Loader2 className="size-3 animate-spin" aria-hidden />
        ) : (
          <RotateCw className="size-3" aria-hidden />
        )}
        {rerunLabel}
      </Button>
    </div>
  );
}

/** Placeholder for a panel whose action has not been run yet. */
export function PanelEmpty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}
